// seed/demo_seed.js
require('dotenv').config();
const pool = require('../src/db');
const bcrypt = require('bcrypt');

(async ()=>{
  try{
    const conn = await pool.getConnection();
    try{
      // ensure DB exists (skip if already created via migrations)
      // create demo user if not exists
      const email = 'worker@example.com';
      const [rows] = await conn.query('SELECT id FROM users WHERE email = ?', [email]);
      if(rows.length > 0){
        console.log('Demo user already exists');
        return process.exit(0);
      }
      const password = 'password123';
      const password_hash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS || '10',10));
      const role_meta = JSON.stringify({ worker_id: 'W001', skills: 'weeding,irrigation' });
      const now = new Date();
      const [res] = await conn.query(
        'INSERT INTO users (name,email,phone,password_hash,role,role_meta,verified,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        ['Demo Worker', email, '', password_hash, 'farm_worker', role_meta, 1, now, now]
      );
      console.log('Demo user created:', email, 'password:', password);
    } finally {
      conn.release();
      process.exit(0);
    }
  }catch(err){
    console.error(err);
    process.exit(1);
  }
})();
