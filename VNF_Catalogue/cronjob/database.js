var mysql = require('mysql');

// Hardcoding some variables for now as crontab does not seem to support
// environment variables.
var pool = mysql.createPool({
  host: 'mysql',
  user: 'vnf_user',
  password: 'vnf_password',
  database: 'vnf_catalogue',
  connectionLimit: 50,
  supportBigNumbers: true,
  multipleStatements: true,
  dateStrings: 'date'
});

exports.pool = pool;
