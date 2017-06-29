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
var async = require('async');

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

var renderer = function(res, error, results) {
    //res.render('project_profile', { title: 'Express', json: results });
    if(error) {
      res.status(500);
      res.send({'error': 'Adding VNF did not succeed'});
      return;
    } else {
      res.end('{"success" : "Updated Successfully", "status" : 200}');
      return;
    }
}


var add_vnf_name_tag = function(vnf_name, vnf_id, cb) {
  db_pool.getConnection(function(err, connection) {
    sql_query = 'INSERT INTO tag(tag_name, is_vnf_name) values(\'' + vnf_name + '\', 1)\;SELECT LAST_INSERT_ID() tag_id';
    connection.query(sql_query, function (error, results, fields) {
        tag_id = results[1][0].tag_id;
        connection.release();
        if(error) {
            cb(null, error, -1, -1);
        } else {
            cb(null, null, vnf_id, tag_id);
        }
      });
  });
}

var add_vnf_tag_relationship = function(err, vnf_id, tag_id, cb) {
  console.log('here');
  console.log(err); console.log(vnf_id); console.log(tag_id); console.log(cb);
  if(err) cb(null, err, -1); // err propagated from add_vnf_name_tag
  db_pool.getConnection(function(err, connection) {
    sql_query = 'INSERT INTO vnf_tags(tag_id, vnf_id) values(' + tag_id + ', ' + vnf_id + ')\;';
    console.log(sql_query);
    connection.query(sql_query, function (error, results, fields) {
        connection.release();
        console.log('here');
        if(error) {
            cb(null, error, -1);
        } else {
            cb(null, null, results);
        }
      });
  });
}


router.post('/', function(req, res) {
  upload(req,res,function(err) {
        console.log(req.body);
        console.log(req.file)
        if(req.file == null && req.body['file_url'] != '') {
            response = 'File Upload error: wrong Filetype, only png supported as of now';
            res.status(500);
            res.end(JSON.stringify({'error': response}));
            return;
        }
        console.log(err);
        if(err) {
            console.log(err);
            response = 'File Upload error: ' + err;
            console.log(response);
            //return res.end(req.fileValidationError);
            res.status(500);
            res.end(JSON.stringify({'error': response}));
            console.log('here here here here');
            return;
        }
        console.log('here here');

        console.log(req.file);
        req.body['photo_url'] = (req.file) ? req.file['filename'] : 'logo.png';
        console.log(req.body);

        req.checkBody("vnf_name", "VNF Name must not be empty").notEmpty();
        req.checkBody("repo_url", "Repository URL must not be empty").notEmpty();
        req.checkBody("license", "Please select a License").notEmpty();
        req.checkBody("opnfv_indicator", "Please select an OPNFV Indicator").notEmpty();
        //req.checkBody("repo_url", "Must be a Github URL").matches('.*github\.com.*');

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

        req.body['vnf_name'] = req.body['vnf_name'].toLowerCase();

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
             sql_query = 'INSERT INTO vnf SET ?; select last_insert_id() vnf_id;'

             connection.query(sql_query, vnf_details, function (error, results, fields) {
                // And done with the connection.
                connection.release();
                //if (error) throw error;
                if(error) {
                    res.status(500);
                    res.send({'error': 'Adding VNF did not succeed'});
                    return;
                } else {

                        console.log(results);
                        console.log(results[1][0].vnf_id);
                        vnf_id = results[1][0].vnf_id;
                        async.waterfall([                                                          
                          async.apply(add_vnf_name_tag, vnf_details['vnf_name'], vnf_id),
                          add_vnf_tag_relationship,
                        ], renderer.bind(null, res));

                    // Handle error after the release.
                    //res.end('{"success" : "Updated Successfully", "status" : 200}');
                    //return;
                }
                // Don't use the connection here, it has been returned to the pool.
            });
          });
        });


  });

});

module.exports = router;
