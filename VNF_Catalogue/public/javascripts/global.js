/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

$(document).ready( function() {
    $('select').material_select();
    $('.modal').modal();
    $(".button-collapse").sideNav();
    $('.carousel').carousel();

    $('#Search').click(function() {
        var tags = $('#Tags').val().toLowerCase().split(/[ ,]+/);
        window.location.href = '/search_projects?tags=' + tags;
        return false;
    });

    $('#SearchSpan').click(function(){
        var tags = $('#Tags').val().toLowerCase().split(/[ ,]+/);
        window.location.href = '/search_projects?tags=' + tags;
        return false;
    });

    $('div.form-group-custom i.material-icons').click(function(e){
        var tags = $('#Tags').val().toLowerCase().split(/[ ,]+/);
        window.location.href = '/search_projects?tags=' + tags;
        return false;
    });

    $("#add_project_button").on('click',function(){
        event.preventDefault();
        var vnf_name = $("#vnf_name").val() ;

        var formData = new FormData($('form#add_project_form')[0]);
        var license = $('#license option:selected').val();
        formData.append('license', license);
        var opnfv_indicator = $('#opnfv_indicator option:selected').val();
        formData.append('opnfv_indicator', opnfv_indicator);

        $.ajax({
            url: '/add_project',
            type: 'post',
            //dataType: 'json',
            processData: false,  // tell jQuery not to process the data
            contentType: false,  // tell jQuery not to set contentType
            data: formData,
            success: function(data) {
                    $('#modal1').modal('close');
                    $('form#add_project_form').trigger('reset');
                    Materialize.toast('Successfully submitted the VNF!', 3000, 'rounded');
            },
            error: function (error) {
                if(error['responseJSON']) {
                    Materialize.toast(error['responseJSON']['error'], 3000, 'rounded');
                } else if(error['responseText']) {
                    var response_message = JSON.parse(error['responseText']);
                    Materialize.toast(response_message['error'], 3000, 'rounded');
                }
                //$('#modal1').modal('open');
            }
        });
    });
    $("#add_tag_button").on('click',function(){
        event.preventDefault();
        var tag_name = $("#tag_name").val() ;

        $.ajax({
            url: '/add_tag',
            type: 'post',
            dataType: 'json',
            data: $('form#add_tag_form').serialize(),
            success: function(data) {
                    $('#modal2').modal('close');
                    $('form#add_tag_form').trigger('reset');
                    Materialize.toast('Successfully submitted the TAG!', 3000, 'rounded');
            },
            error: function (error) {
                Materialize.toast(error['responseJSON']['error'], 3000, 'rounded');
            }
        });
    });

    var QueryString = function () {
        // This function is anonymous, is executed immediately and 
        // the return value is assigned to QueryString!
        var query_string = {};
        var query = window.location.search.substring(1);
        var vars = query.split("&");
        for (var i=0;i<vars.length;i++) {
        var pair = vars[i].split("=");
        // If first entry with this name
        if (typeof query_string[pair[0]] === "undefined") {
            query_string[pair[0]] = decodeURIComponent(pair[1]);
            // If second entry with this name
        } else if (typeof query_string[pair[0]] === "string") {
            var arr = [ query_string[pair[0]],decodeURIComponent(pair[1]) ];
            query_string[pair[0]] = arr;
        // If third or later entry with this name
        } else {
                query_string[pair[0]].push(decodeURIComponent(pair[1]));
            }
        } 
        return query_string;
    };

});
