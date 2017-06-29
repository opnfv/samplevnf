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

/* Post Controller for Tag autocomplete form */
router.post('/', function(req, res) {
    console.log('here here here here');
    order_key = req.param('order_key');
    db_pool.getConnection(function(err, connection) {

        sql_query = 'select * from vnf order by ' + order_key + ' desc limit 8';
        // TODO find why it works and not above
        console.log(sql_query);
        connection.query(sql_query, function (error, results, fields) {
            console.log(results);

            console.log(results);
            connection.release();
            if (error) {
                res.end(JSON.stringify({}));
            } else {
                res.end(JSON.stringify(results));    
            }
        });
    });
});

module.exports = router;
