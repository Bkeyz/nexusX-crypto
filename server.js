require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Force HTTPS (Render already provides SSL, but this redirects HTTP → HTTPS)
app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
        return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
});

// Helper functions
function generateToken(userId, email, isAdmin, isVerified = true) {
    return jwt.sign({ userId, email, isAdmin, isVerified }, JWT_SECRET, { expiresIn: '7d' });
}

async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.substring(7);
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function requireAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// Daily profit calculation
async function calculateDailyProfits() {
    console.log('🔄 Running daily profit calculation...', new Date().toISOString());
    const { data: investments, error } = await supabase
        .from('user_investments')
        .select('*, users(id, wallet_balance, total_profit)')
        .eq('status', 'active');
    if (error || !investments || investments.length === 0) {
        console.log('No active investments');
        return;
    }
    console.log(`📊 Found ${investments.length} active investments`);
    for (const inv of investments) {
        const dailyProfit = (inv.amount * inv.daily_profit_rate) / 100;
        const newBalance = (inv.users.wallet_balance || 0) + dailyProfit;
        const newTotalProfit = (inv.users.total_profit || 0) + dailyProfit;
        await supabase
            .from('users')
            .update({ wallet_balance: newBalance, total_profit: newTotalProfit })
            .eq('id', inv.user_id);
        await supabase
            .from('user_investments')
            .update({ last_profit_date: new Date() })
            .eq('id', inv.id);
        await supabase
            .from('transactions')
            .insert({
                user_id: inv.user_id,
                type: 'profit',
                amount: dailyProfit,
                status: 'completed',
                description: `Daily profit from investment #${inv.id} (${inv.daily_profit_rate}%)`
            });
        console.log(`✅ Added $${dailyProfit.toFixed(2)} profit to user ${inv.user_id}`);
        if (new Date() >= new Date(inv.end_date)) {
            await supabase.from('user_investments').update({ status: 'completed' }).eq('id', inv.id);
            console.log(`📅 Investment #${inv.id} completed`);
        }
    }
    console.log('✅ Daily profit calculation finished');
}

// Schedule cron job (daily at 00:01 Lagos time)
cron.schedule('1 0 * * *', async () => {
    console.log('⏰ Running scheduled profit calculation...');
    await calculateDailyProfits();
}, { timezone: "Africa/Lagos" });
console.log('⏰ Profit calculator scheduled daily at 00:01 AM (Lagos time)');

// ========== PUBLIC ROUTES ==========
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Public investment plans (no login required)
app.get('/api/public-plans', async (req, res) => {
    const { data: plans } = await supabase
        .from('plans')
        .select('*')
        .eq('is_active', true)
        .order('min_amount', { ascending: true });
    res.json({ plans: plans || [] });
});

// ========== USER ROUTES ==========
app.post('/api/register', async (req, res) => {
    const { full_name, email, password } = req.body;
    if (!full_name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
    const { data: existing } = await supabase.from('users').select('email').eq('email', email).single();
    if (existing) return res.status(400).json({ error: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data: newUser, error } = await supabase
        .from('users')
        .insert({ full_name, email, password: hashedPassword, wallet_balance: 0, total_deposited: 0, total_withdrawn: 0, total_profit: 0, is_active: true, is_verified: true, is_admin: false })
        .select()
        .single();
    if (error) return res.status(500).json({ error: 'Registration failed' });
    const token = generateToken(newUser.id, newUser.email, false);
    res.json({ success: true, message: 'Account created!', token, user: { id: newUser.id, full_name: newUser.full_name, email: newUser.email, wallet_balance: newUser.wallet_balance } });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.is_active) return res.status(401).json({ error: 'Account suspended' });
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    await supabase.from('users').update({ last_login: new Date() }).eq('id', user.id);
    const token = generateToken(user.id, user.email, user.is_admin || false);
    res.json({ success: true, message: 'Login successful!', token, user: { id: user.id, full_name: user.full_name, email: user.email, wallet_balance: user.wallet_balance, total_deposited: user.total_deposited || 0, total_withdrawn: user.total_withdrawn || 0, total_profit: user.total_profit || 0, is_admin: user.is_admin || false } });
});

app.get('/api/dashboard', verifyToken, async (req, res) => {
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.userId).single();
    const { data: transactions } = await supabase.from('transactions').select('*').eq('user_id', req.user.userId).order('created_at', { ascending: false }).limit(10);
    const { data: plans } = await supabase.from('plans').select('*').eq('is_active', true);
    res.json({ user: { full_name: user.full_name, wallet_balance: user.wallet_balance, total_deposited: user.total_deposited || 0, total_withdrawn: user.total_withdrawn || 0, total_profit: user.total_profit || 0 }, transactions: transactions || [], plans: plans || [] });
});

app.post('/api/deposit', verifyToken, async (req, res) => {
    const { amount, crypto_type } = req.body;
    if (!amount || amount < 10) return res.status(400).json({ error: 'Minimum deposit is $10' });
    const { data: deposit, error } = await supabase.from('deposits').insert({ user_id: req.user.userId, amount, crypto_type: crypto_type || 'USDT', status: 'pending' }).select().single();
    if (error) return res.status(500).json({ error: 'Failed to create deposit request' });
    const addresses = { USDT: process.env.USDT_ADDRESS || '0x1234567890abcdef1234567890abcdef12345678', BTC: process.env.BTC_ADDRESS || 'bc1qxyzabc1234567890', ETH: process.env.ETH_ADDRESS || '0xabcdef1234567890abcdef1234567890abcdef12' };
    res.json({ success: true, message: 'Deposit request submitted', deposit, address: addresses[crypto_type || 'USDT'] });
});

app.post('/api/withdraw', verifyToken, async (req, res) => {
    const { amount, wallet_address, crypto_type } = req.body;
    if (!amount || !wallet_address) return res.status(400).json({ error: 'Amount and address required' });
    const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.user.userId).single();
    if (user.wallet_balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    const { data: withdrawal, error } = await supabase.from('withdrawals').insert({ user_id: req.user.userId, amount, wallet_address, crypto_type: crypto_type || 'USDT', status: 'pending' }).select().single();
    if (error) return res.status(500).json({ error: 'Withdrawal request failed' });
    res.json({ success: true, message: 'Withdrawal request submitted', withdrawal });
});

app.post('/api/support/ticket', verifyToken, async (req, res) => {
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });
    const { data: ticket, error } = await supabase.from('tickets').insert({ user_id: req.user.userId, subject, message, status: 'open' }).select().single();
    if (error) return res.status(500).json({ error: 'Failed to create ticket' });
    res.json({ success: true, message: 'Ticket created', ticket });
});

app.get('/api/support/tickets', verifyToken, async (req, res) => {
    const { data: tickets } = await supabase.from('tickets').select('*').eq('user_id', req.user.userId).order('created_at', { ascending: false });
    res.json({ tickets: tickets || [] });
});

// ========== INVESTMENT ROUTE ==========
app.post('/api/invest', verifyToken, async (req, res) => {
    const { planId, amount } = req.body;
    if (!planId || !amount) return res.status(400).json({ error: 'Plan ID and amount required' });
    const { data: plan } = await supabase.from('plans').select('*').eq('id', planId).single();
    if (!plan || !plan.is_active) return res.status(404).json({ error: 'Plan not available' });
    if (amount < plan.min_amount) return res.status(400).json({ error: `Minimum investment is $${plan.min_amount}` });
    if (plan.max_amount && amount > plan.max_amount) return res.status(400).json({ error: `Maximum investment is $${plan.max_amount}` });
    const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.user.userId).single();
    if (user.wallet_balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    await supabase.from('users').update({ wallet_balance: user.wallet_balance - amount }).eq('id', req.user.userId);
    const endDate = new Date(); endDate.setDate(endDate.getDate() + plan.duration_days);
    const { data: investment, error } = await supabase.from('user_investments').insert({ user_id: req.user.userId, plan_id: plan.id, amount, daily_profit_rate: plan.daily_profit, start_date: new Date(), end_date: endDate, last_profit_date: new Date(), status: 'active', total_profit_earned: 0 }).select().single();
    if (error) {
        await supabase.from('users').update({ wallet_balance: user.wallet_balance }).eq('id', req.user.userId);
        return res.status(500).json({ error: 'Investment failed' });
    }
    await supabase.from('transactions').insert({ user_id: req.user.userId, type: 'investment', amount, status: 'completed', description: `Invested in ${plan.name} plan` });
    res.json({ success: true, message: `Invested $${amount} into ${plan.name} plan`, investment });
});

// ========== ADMIN ROUTES ==========
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    const { data: admin } = await supabase.from('users').select('*').eq('email', email).eq('is_admin', true).single();
    if (!admin) return res.status(401).json({ error: 'Admin access only' });
    if (email === 'admin@nexusx.com' && password === 'admin123') {
        const token = generateToken(admin.id, admin.email, true);
        return res.json({ success: true, token, admin: { id: admin.id, full_name: admin.full_name, email: admin.email } });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/api/admin/users', verifyToken, requireAdmin, async (req, res) => {
    const { data: users } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    const { data: pendingDeposits } = await supabase.from('deposits').select('amount').eq('status', 'pending');
    const { data: pendingWithdrawals } = await supabase.from('withdrawals').select('amount').eq('status', 'pending');
    res.json({ users: users || [], stats: { total_users: users?.length || 0, pending_deposits: pendingDeposits?.length || 0, pending_deposits_amount: pendingDeposits?.reduce((s, d) => s + d.amount, 0) || 0, pending_withdrawals: pendingWithdrawals?.length || 0 } });
});

app.post('/api/admin/user-action', verifyToken, requireAdmin, async (req, res) => {
    const { email, amount, note, action } = req.body;
    if (!email || !amount || amount <= 0) return res.status(400).json({ error: 'Email and valid amount required' });
    const { data: user } = await supabase.from('users').select('id, wallet_balance, total_deposited, total_withdrawn, total_profit').eq('email', email).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    let newBalance = user.wallet_balance, newTotalDeposited = user.total_deposited || 0, newTotalWithdrawn = user.total_withdrawn || 0, newTotalProfit = user.total_profit || 0, msg = '';
    switch (action) {
        case 'add': newBalance += amount; newTotalDeposited += amount; msg = `Added $${amount} to balance`; break;
        case 'deduct': if (user.wallet_balance < amount) return res.status(400).json({ error: 'Insufficient balance' }); newBalance -= amount; newTotalWithdrawn += amount; msg = `Deducted $${amount} from balance`; break;
        case 'profit': newBalance += amount; newTotalProfit += amount; msg = `Added $${amount} profit`; break;
        default: return res.status(400).json({ error: 'Invalid action' });
    }
    await supabase.from('users').update({ wallet_balance: newBalance, total_deposited: newTotalDeposited, total_withdrawn: newTotalWithdrawn, total_profit: newTotalProfit }).eq('id', user.id);
    await supabase.from('transactions').insert({ user_id: user.id, type: action === 'deduct' ? 'withdrawal' : 'deposit', amount, status: 'completed', description: note || msg });
    res.json({ success: true, message: `${msg} for ${email}` });
});

app.get('/api/admin/pending-deposits', verifyToken, requireAdmin, async (req, res) => {
    const { data: deposits } = await supabase.from('deposits').select('*, users(full_name, email)').eq('status', 'pending').order('created_at', { ascending: true });
    res.json({ deposits: deposits || [] });
});
app.post('/api/admin/approve-deposit', verifyToken, requireAdmin, async (req, res) => {
    const { transaction_id, user_id, amount } = req.body;
    await supabase.from('deposits').update({ status: 'approved', processed_at: new Date() }).eq('id', transaction_id);
    const { data: user } = await supabase.from('users').select('wallet_balance, total_deposited').eq('id', user_id).single();
    await supabase.from('users').update({ wallet_balance: user.wallet_balance + amount, total_deposited: (user.total_deposited || 0) + amount }).eq('id', user_id);
    res.json({ success: true });
});
app.get('/api/admin/pending-withdrawals', verifyToken, requireAdmin, async (req, res) => {
    const { data: withdrawals } = await supabase.from('withdrawals').select('*, users(full_name, email, wallet_balance)').eq('status', 'pending').order('created_at', { ascending: true });
    res.json({ withdrawals: withdrawals || [] });
});
app.post('/api/admin/approve-withdrawal', verifyToken, requireAdmin, async (req, res) => {
    const { withdrawal_id, user_id, amount } = req.body;
    await supabase.from('withdrawals').update({ status: 'approved', processed_at: new Date() }).eq('id', withdrawal_id);
    const { data: user } = await supabase.from('users').select('wallet_balance, total_withdrawn').eq('id', user_id).single();
    await supabase.from('users').update({ wallet_balance: user.wallet_balance - amount, total_withdrawn: (user.total_withdrawn || 0) + amount }).eq('id', user_id);
    res.json({ success: true });
});
app.get('/api/admin/tickets', verifyToken, requireAdmin, async (req, res) => {
    const { data: tickets } = await supabase.from('tickets').select('*, users(full_name, email)').order('created_at', { ascending: false });
    res.json({ tickets: tickets || [] });
});
app.post('/api/admin/reply-ticket', verifyToken, requireAdmin, async (req, res) => {
    const { ticket_id, reply } = req.body;
    await supabase.from('tickets').update({ admin_reply: reply, status: 'closed', updated_at: new Date() }).eq('id', ticket_id);
    res.json({ success: true });
});
app.get('/api/admin/plans', verifyToken, requireAdmin, async (req, res) => {
    const { data: plans } = await supabase.from('plans').select('*').order('min_amount', { ascending: true });
    res.json({ plans: plans || [] });
});
app.post('/api/admin/update-plan', verifyToken, requireAdmin, async (req, res) => {
    const { id, name, min_amount, max_amount, daily_profit, duration_days, is_active } = req.body;
    if (!id || !name || !min_amount || !daily_profit || !duration_days) return res.status(400).json({ error: 'All fields required' });
    const { data: updatedPlan, error } = await supabase.from('plans').update({ name, min_amount, max_amount: max_amount || null, daily_profit, duration_days, is_active }).eq('id', id).select().single();
    if (error) return res.status(500).json({ error: 'Failed to update plan' });
    res.json({ success: true, plan: updatedPlan });
});
app.post('/api/admin/create-plan', verifyToken, requireAdmin, async (req, res) => {
    const { name, min_amount, max_amount, daily_profit, duration_days } = req.body;
    if (!name || !min_amount || !daily_profit || !duration_days) return res.status(400).json({ error: 'All fields required' });
    const { data: newPlan, error } = await supabase.from('plans').insert({ name, min_amount, max_amount: max_amount || null, daily_profit, duration_days, is_active: true }).select().single();
    if (error) return res.status(500).json({ error: 'Failed to create plan' });
    res.json({ success: true, plan: newPlan });
});
app.post('/api/admin/calculate-profits', verifyToken, requireAdmin, async (req, res) => {
    await calculateDailyProfits();
    res.json({ success: true, message: 'Profit calculation triggered' });
});

// ========== SERVE FRONTEND ==========
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ========== START SERVER ==========
app.listen(PORT, () => {
    console.log(`\n🚀 NexusX Server running on http://localhost:${PORT}`);
    console.log(`👤 User site: http://localhost:${PORT}`);
    console.log(`🔐 Admin site: http://localhost:${PORT}/admin.html`);
});