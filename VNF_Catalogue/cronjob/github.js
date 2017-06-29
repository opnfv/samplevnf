// Important Add your access token here default rate of github is limited to 60 API calls per hour
var access_token = '523825265638c8f2b5b9f1d1f5af31d71bceb49c';
// Important set the delta threshold for repo details updation. For instance if the threshold is
// set to 1 day(60 * 60 * 24), the cronjob will only update the row if the difference between current
// time and last_updated time stamp of a repo is greater than one day
var delta = 60 * 60 * 24;


var github = require('octonode');
db_pool = require('/usr/src/app/database').pool;
async = require('async');

var current_time = Math.floor(new Date().getTime() / 1000);//toISOString().slice(0, 19).replace('T', ' ');
console.log(current_time);

var get_val_from_header = function(header_link) {
    // small hack by parsing the header and setting per_page = 1, hence no pagination fetch required
    result_intermediate = header_link.split(';');
    result_intermediate = result_intermediate[result_intermediate.length - 2];
    var reg = /&page=([0-9].*)>/g;
    var match = reg.exec(result_intermediate);
    return parseInt(match[1]);
}

var get_stargazers = function(result, ghrepo, orig_repo, primary_callback, cb) {
    ghrepo.stargazers({per_page: 1}, function(err, data, headers) {
    //console.log(JSON.stringify(data));
        try {
            result['no_of_stars'] = get_val_from_header(headers['link']);
            cb(null, result, ghrepo, orig_repo, primary_callback);
        } catch(err) {
            result['no_of_stars'] = null;
            cb(null, result, ghrepo, orig_repo, primary_callback);
        }
    });
}

var get_branches = function(result, ghrepo, orig_repo, primary_callback, cb) {
    ghrepo.branches({per_page: 1}, function(err, data, headers) {
        try {
            result['versions'] = get_val_from_header(headers['link']);
            cb(null, result, ghrepo, orig_repo, primary_callback);
        } catch(err) {
            result['versions'] = null;
            cb(null, result, ghrepo, orig_repo, primary_callback);
        }
    });
}

var get_contributors = function(result, ghrepo, orig_repo, primary_callback, cb) {
    ghrepo.contributors({per_page: 1}, function(err, data, headers) {
        try {
            result['no_of_developers'] = get_val_from_header(headers['link']);
            cb(null, result, ghrepo, orig_repo, primary_callback);
        } catch(err) {
            result['no_of_developers'] = null;
            cb(null, result, ghrepo, orig_repo, primary_callback);
        }
    });
}

var get_lines_of_code = function(result, ghrepo, orig_repo, primary_callback, cb) {
    //    #TODO
    console.log('here');

    console.log(orig_repo);
    const
        spawn = require( 'child_process' ).spawn,
        ls = spawn( 'bash', ['/usr/src/app/git_count_loc.sh', orig_repo] );

    ls.stdout.on( 'data', data => {
        console.log( `stdout: ${data}` );
        result['lines_of_code'] = parseInt(`${data}`.replace(/\n$/, ''), 10);
        //cb(null, result, primary_callback);
    });

    ls.stderr.on( 'data', data => {
        //console.log( `stderr: ${data}` );
        //cb(null, result, primary_callback);
    });

    ls.on( 'close', code => {
        console.log( `child process exited with code ${code}` );
        cb(null, result, primary_callback);
    });
}

var secondary_callback = function (err, result, primary_callback) {
    console.log(result);
    if((result['last_updated'] == null) || (current_time - result['last_updated'] > delta)) {
        db_pool.getConnection(function(err, connection) {
            //Use the connection
            var last_updated = current_time;
            var no_of_stars = result['no_of_stars'];
            var versions = result['versions'];
            var no_of_developers = result['no_of_developers'];
            var lines_of_code = result['lines_of_code'];
            console.log('here');
            console.log(lines_of_code);
            sql_query = 'update vnf set last_updated = FROM_UNIXTIME(' + last_updated;
            sql_query += '), no_of_stars =  ' + no_of_stars + ', versions = ' + versions;
            sql_query += ', lines_of_code = ' + lines_of_code;
            sql_query += ', no_of_developers = ' + no_of_developers + ' where vnf_id = ';
            sql_query += result['vnf_id'];
            console.log(sql_query);
            connection.query(sql_query, function (error, results, fields) {
                //if (error) throw error;
                //And done with the connection.
                connection.release();
                if(error) {
                    primary_callback(null, result['vnf_id'] + ' not updated');
                } else {
                    primary_callback(null, result['vnf_id'] + ' updated');
                }
                // Handle error after the release.
                // Don't use the connection here, it has been returned to the pool.
            });
        });
    } else {
        primary_callback(null, result['vnf_id'] + ' not updated');
    }
}

var get_stats = function(vnf_details, callback) {
    repo = vnf_details['repo_url'];
    orig_repo = repo;
    repo = repo.split("/");
    github_id = repo[repo.length - 2] + '/' + repo[repo.length - 1];

    var async = require('async');
    var client = github.client(access_token);
    var ghrepo = client.repo(github_id);

    result = {}
    result['vnf_id'] = vnf_details['vnf_id'];
    result['last_updated'] = vnf_details['last_updated'];

    async.waterfall([
            async.apply(get_stargazers, result, ghrepo, orig_repo, callback),
            get_branches,
            get_contributors,
            get_lines_of_code,
        ], secondary_callback);
}

db_pool.getConnection(function(err, connection) {
    sql_query = 'select vnf_id, repo_url, UNIX_TIMESTAMP(last_updated) last_updated from vnf';
    console.log(sql_query);
    connection.query(sql_query, function (error, results, fields) {
        if (error) throw error;
        async.map(results, get_stats, function(error, results) {
            //console.log(results);
            console.log(results);
            process.exit();

        });
    });
});

