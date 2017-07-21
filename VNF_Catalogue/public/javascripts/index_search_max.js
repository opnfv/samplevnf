/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

$(document).ready( function() {
    //alert('index saeerch max ....');
    var lines_of_code_string = `
        <div class="box-container">
          <div class="col-md-3">
            <div class="content-box">
              <div class="content-data">
                <h1 class="content-title"><a href="/project_profile?vnf_id=%vnf_id">%vnf_name%</a></h1>
                <div class="box"><img class="img-size commit-icon" src="/uploads/%photo_url%"/>
                  <h3 class="commits">%lines_of_code%<br/>Lines Of Code</h3>
                </div>
              </div>
            </div>
          </div>
        </div>
    `;

    var no_of_developers_string = `
        <div class="box-container">
          <div class="col-md-3">
            <div class="content-box">
              <div class="content-data">
                <h1 class="content-title"><a href="/project_profile?vnf_id=%vnf_id">%vnf_name%</a></h1>
                <div class="box"><img class="img-size commit-icon" src="/uploads/%photo_url%"/>
                  <h3 class="commits">%no_of_developers%<br/>No Of Developers</h3>
                </div>
              </div>
            </div>
          </div>
        </div>
    `;

    var no_of_stars_string = `
        <div class="box-container">
          <div class="col-md-3">
            <div class="content-box">
              <div class="content-data">
                <h1 class="content-title"><a href="/project_profile?vnf_id=%vnf_id">%vnf_name%</a></h1>
                <div class="box"><img class="img-size commit-icon" src="/uploads/%photo_url%"/>
                  <h3 class="commits">%no_of_stars%<br/>No Of Stars</h3>
                </div>
              </div>
            </div>
          </div>
        </div>
    `;

    var search_max_result = function(string1, result) {
        var string_replacement = {};
        //alert(JSON.stringify(result));
        
        for (var k in result) {
            if (result.hasOwnProperty(k)) {
                string_replacement['%' + k + '%'] = result[k];
                if(!string_replacement['%' + k + '%']) {
                    string_replacement['%' + k + '%'] = -1;
                }
            }
        }
        //alert(JSON.stringify(string_replacement));
        
        string1 = string1.replace(/%\w+%/g, function(all) {
            return string_replacement[all] || all;
        });
        //alert(JSON.stringify(string1));
        return string1;
    };

    $("#lines_of_code").on('click',function(){
        event.preventDefault();
        var json_data = {};
        json_data['order_key'] = 'lines_of_code';
        $.ajax({
            url: '/search_max',
            type: 'post',
            dataType: 'json',
            data: json_data,
            success: function(data) {
                    html_string = '';
                    for(var result in data) {
                        html_string += search_max_result(lines_of_code_string, data[result]);
                    }
                    $('#content').html(html_string);

            },
            error: function (error) {
                Materialize.toast(error['responseJSON']['error'], 3000, 'rounded');
            }
        });
    });

    $("#no_of_developers").on('click',function(){
        event.preventDefault();
        var json_data = {};
        json_data['order_key'] = 'no_of_developers';
        $.ajax({
            url: '/search_max',
            type: 'post',
            dataType: 'json',
            data: json_data,
            success: function(data) {
                    html_string = '';
                    for(var result in data) {
                        html_string += search_max_result(no_of_developers_string, data[result]);
                    }
                    $('#content').html(html_string);
            },
            error: function (error) {
                Materialize.toast('', 3000, 'rounded');
            }
        });
    });

    $("#no_of_stars").on('click',function(){
        event.preventDefault();
        var json_data = {};
        json_data['order_key'] = 'no_of_stars';
        $.ajax({
            url: '/search_max',
            type: 'post',
            dataType: 'json',
            data: json_data,
            success: function(data) {
                    html_string = '';
                    for(var result in data) {
                        html_string += search_max_result(no_of_stars_string, data[result]);
                    }
                    $('#content').html(html_string);
            },
            error: function (error) {
                Materialize.toast('', 3000, 'rounded');
            }
        });
    });

});
