const mysql = require('mysql2')

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'mysql', // nama service
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'smart-train'
})


module.exports = pool.promise()
