/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

var express = require('express');
var router = express.Router();
var multer = require('multer');

var max_size = 1 * 1000 * 1000; // image size_limit

var storage =   multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, './public/uploads');
  },
  filename: function (req, file, callback) {
    console.log(file);
    console.log(req.body);
    callback(null, file.fieldname + '-' + Date.now() + '.png');
  }
});

var fileFilter = function (req, file, cb) {
  if (file.mimetype !== 'image/png') {
    //req.fileValidationError = 'goes wrong on the mimetype';
    cb(null, false);
  } else {
    cb(null, true);
  }
}

var upload = multer({ fileFilter: fileFilter, limits: { fileSize: max_size }, storage : storage}).single('file_upload');


router.post('/', function(req, res) {
  upload(req,res,function(err) {
        console.log(req.body);
        console.log(req.file)
        if(req.file == null && req.body['file_url'] != '') {
            response = 'File Upload error: wrong Filetype, only png supported as of now';
            res.status(500);
            res.end(JSON.stringify({'error': response}));

        }
        if(err) {
            console.log(err);
            response = 'File Upload error: ' + err;
            console.log(response);
            //return res.end(req.fileValidationError);
            res.status(500);
            res.end(JSON.stringify({'error': response}));
            return;
        }

        console.log(req.file);
        req.body['photo_url'] = (req.file) ? req.file['filename'] : 'logo.png';
        console.log(req.body);

        req.checkBody("vnf_name", "VNF Name must not be empty").notEmpty();
        req.checkBody("repo_url", "Repository URL must not be empty").notEmpty();
        req.checkBody("license", "Please select a License").notEmpty();
        req.checkBody("opnfv_indicator", "Please select an OPNFV Indicator").notEmpty();
        req.checkBody("repo_url", "Must be a Github URL").matches('.*github\.com.*');

        var errors = req.validationErrors();
        console.log(errors);

        var response = '';  for(var i = 0; i < errors.length; i++) {
            console.log(errors[i]['msg']);
            response = response + errors[i]['msg'] + '; ';
        }

        if(errors) {    res.status(500);
            res.send({'error': response});
            return;
        }

        var vnf_details = req.body;
        delete vnf_details.file_url;

        db_pool.getConnection(function(err, connection) {
            // Use the connection

          sql_query = 'INSERT INTO photo(photo_url) values(\'' + req.body['photo_url'] + '\')\;SELECT LAST_INSERT_ID() photo_id';
          // TODO look above query prone to sql_injections

          console.log(sql_query);
          connection.query(sql_query, function (error, results, fields) {
             console.log('hola');
             console.log(results[1][0].photo_id);
              //connection.query(sql_query, vnf_details, function (error, results, fields) {
             delete vnf_details.photo_url;
             vnf_details['photo_id'] = results[1][0].photo_id;
             sql_query = 'INSERT INTO vnf SET ?'
               connection.query(sql_query, vnf_details, function (error, results, fields) {
             // And done with the connection.
             connection.release();
             if (error) throw error;

             // Handle error after the release.
             res.end('{"success" : "Updated Successfully", "status" : 200}');
             return;
               // Don't use the connection here, it has been returned to the pool.
               });
          });
        });


  });

});

module.exports = router;
