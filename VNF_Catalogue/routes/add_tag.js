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

router.post('/', function(req, res) {
  console.log(req.body);
  req.checkBody("tag_name", "TAG Name must not be empty").notEmpty();

  var errors = req.validationErrors();
  console.log(errors);

  var response = '';  for(var i = 0; i < errors.length; i++) {
    console.log(errors[i]['msg']);
    response = response + errors[i]['msg'] + '; ';
  }

  if(errors) {  res.status(500);
    res.send({'error': response});
    return;
  }

  req.body['tag_name'] = req.body['tag_name'].toLowerCase();
  var tag_details = req.body;

  db_pool.getConnection(function(err, connection) {
    // Use the connection
    sql_query = 'INSERT INTO tag SET ?'
    connection.query(sql_query, tag_details, function (error, results, fields) {
        // And done with the connection.
        // Handle error after the release.
        console.log('here');
        if(error) {
            res.end('{"error" : "Adding tag did not succeed", "status" : 500}');
            connection.release();
            return;
        } else {
            res.end('{"success" : "Updated Successfully", "status" : 200}'); 
            connection.release();
            return;
        }
        //if (error) throw error;
        // Don't use the connection here, it has been returned to the pool.
    });
  });


  //res.end('{"success" : "Updated Successfully", "status" : 200}');
  //return;

});

module.exports = router;
