const User = require('../models/userModel');
const md5 = require('md5');
const { blacklistCheck } = require('../utils/security');

exports.register_get = (req, res) => {
    res.render('register', { error: null });
};

exports.register_post = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!blacklistCheck(email)) {
            return res.render('register', { error: 'Watchu tryna do, dawg?' });
        }

        const existingUser = await User.findByEmail(email);
        if (existingUser) {
            return res.render('register', { error: 'Email already exists' });
        }

        await User.createUser(email, password);
        res.redirect('/auth/login');
    } catch (error) {
        res.render('register', { error: 'Server error' });
    }
};

exports.login_get = (req, res) => {
    res.render('login', { error: null });
};

exports.login_post = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!blacklistCheck(email)) {
            return res.render('register', { error: 'Watchu tryna do, dawg?' });
        }

        const user = await User.findByEmail(email);
        if (!user || user.password !== md5(password)) {
            return res.render('login', { error: 'Invalid credentials' });
        }

        req.session.userEmail = user.email;
        res.redirect('/dashboard');
    } catch (error) {
        res.render('login', { error: 'Server error' });
    }
};

exports.logout_get = (req, res) => {
    req.session.destroy(() => {
        res.redirect('/auth/login');
    });
};
