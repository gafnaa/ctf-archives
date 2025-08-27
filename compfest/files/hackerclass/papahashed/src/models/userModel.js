const pool = require('../config/db');
const md5 = require('md5');

class User {
    static async createUser(email, password) {
        const hashedPassword = md5(password);
        const query = `INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email`;
        const result = await pool.query(query, [email, hashedPassword]);
        return result.rows[0];
    }

    static async findByEmail(email) {
        const query = `SELECT * FROM users WHERE email = '${email}'`;
        const result = await pool.query(query);
        return result.rows[0];
    }
}

module.exports = User;