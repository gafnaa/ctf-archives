require('dotenv').config();
const pool = require('./config/db');
const md5 = require('md5');

const seedDB = async () => {
    try {
        console.log('🌱 Seeding database...');

        // Create table if not exists
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            );
        `);

        // Insert default users
        await pool.query(`
            INSERT INTO users (email, password) VALUES 
            ('admin@ristek.com', '${md5(process.env.ADMIN_PASSWORD)}')
            ON CONFLICT (email) DO NOTHING;
        `);

        console.log('✅ Database seeded successfully!');
    } catch (err) {
        console.error('❌ Seeding error:', err);
    }
};

// Export function to be called in server.js
module.exports = seedDB;
