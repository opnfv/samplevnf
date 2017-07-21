/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var validator = require('express-validator');

var routes = require('./routes/index');
var search_projects = require('./routes/search_projects');
var search_projects_results = require('./routes/search_projects_results');
var search_max = require('./routes/search_max');
var project_profile = require('./routes/project_profile');
var add_project = require('./routes/add_project');
var add_tag = require('./routes/add_tag');
var search_tag = require('./routes/search_tag');
var search_vnf = require('./routes/search_vnf');
var vnf_tag_association = require('./routes/vnf_tag_association');
//var project_profile = require('./routes/project_profile');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

db_pool = require('./database').pool;
minio_client = require('./minio').minio_client;
// Database
//var db = require('mysql2');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(validator());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// create minio bucket if it does not exist
minio_client.makeBucket('opnfv-vnfcatalogue', 'us-east-1', function(err) {
    if (err) {
        return console.log(err);
    } else {
        console.log('Bucket created successfully in "us-east-1".');
    }
});

// Make our db accessible to our router
app.use(function(req,res,next){
    //db_pool size 50 default
    req.db_pool = db_pool;
    req.minio = minio_client;
    next();
});

app.use('/', routes);
app.use('/search_projects', search_projects);
app.use('/search_projects_results', search_projects_results);
app.use('/project_profile', project_profile);
app.use('/add_project', add_project);
app.use('/add_tag', add_tag);
app.use('/search_tag', search_tag);
app.use('/search_vnf', search_vnf);
app.use('/vnf_tag_association', vnf_tag_association);
app.use('/search_max', search_max);
//app.use('/', project_profile);
// Some Error handling for now #TODO Remove

/// catch 404 and forwarding to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});


// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

module.exports = app;
