const express = require('express');
const router = express.Router();
const authRoutes = require('./authRoutes.js');

router.use('/auth', authRoutes);
router.get('/dashboard', (req, res) => {
    if (!req.session.userEmail) {
        return res.redirect('/auth/login');
    }
    res.render('dashboard', { email: req.session.userEmail, flag: process.env.FLAG });
});

module.exports = router;