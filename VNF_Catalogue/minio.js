var Minio = require("minio");

var minio_client = new Minio.Client({
    endPoint: 'localhost',//process.env.MINIO_HOST,
    port: 9000,
    secure: false,
    accessKey: process.env.MINIO_ACCESS_KEY,
    secretKey: process.env.MINIO_SECRET_KEY
});

exports.minio_client = minio_client;
