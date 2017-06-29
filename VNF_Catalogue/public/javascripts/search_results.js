/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

$(document).ready( function() {
	var search_result_string_1 = `
		<div class = "container container-custom">
		<div class="card card-shadow-custom horizontal">
		  <div class="row row-custom">
		    
		    <div class="col s5 card-title-div-custom">
		      <span class="card-title card-title-span-custom">
		        <a class="custom-href" href="/project_profile?vnf_id=%vnf_id%">%vnf_name%</a>
		      </span>
		    </div>
		    
		    <div class="col s5 card-title-div-custom">
		      <i class="material-icons">grade</i>
		      <span class="card-title">PenguinScore: 42</span>
		    </div>
		    
		    <div class="col s2 card-title-div-custom-right">
		      <form action="#">
		        <input id="search_result_1" type="checkbox" name="%vnf_name%"/>
		        <label for="search_result_1">Compare</label>
		      </form>
		    </div>
		    
		    <div class="col s4 card-image card-image-custom">
		      <img class="img-size card-image-picture-custom" src="/uploads/%photo_url%"/>
		    </div>
		    
		    <div class="col s8 card-stacked">
		      <div class="card-content">
		        <p>
		          <div class="collection collection-custom">
		            <a class="collection-item" href="#!">
		              <span>
		                <i class="material-icons">code</i>                            
		                Lines Of Code: %lines_of_code%
		              </span>
		            </a>
		            <a class="collection-item" href="#!">
		              <span>
		                <i class="material-icons">person</i>
		                Number of Developers: %no_of_developers%;
		              </span>
		            </a>
		            <a class="collection-item" href="#!">
		              <span>
		                <i class="material-icons">star</i>
		                Number of Stars: %no_of_stars%
		              </span>
		            </a>
		            <a class="collection-item" href="#!">
		              <span>
		                <i class="material-icons">description</i>
		                Number of Versions: %versions%
		              </span>
		            </a>
		          </div>
		        </p>
		      </div>
		      <div class="card-action">
		        Tags:
		    `;
    var search_result_string_2 = `
		        <div class="chip"><a class="a-custom" href="#!">tag1</a></div>
		        <div class="chip"><a class="a-custom" href="#!">Tag2</a></div>
		        <div class="chip"><a class="a-custom" href="#!">Tag3</a></div>
		        <div class="chip"><a class="a-custom" href="#!">Tag4</a></div>
		        <div class="chip"><a class="a-custom" href="#!">Tag5</a></div>
		`;
	var search_result_string_3 = `
		        <a class="a-custom-more" href="/project_profile?vnf_id=%vnf_id%">
		          more
		        </a>
		      </div>
		    </div>
		    
		    <div class="divider"></div>
		    
		    <div class="card-action-custom col s12 card-action">
		      License: <a href="#">%license%</a>
		      Complexity: <a href="#">Atomic</a>
		      Activity: <a href="#">Medium</a>
		      OPNFV Indicator: <a href="#">%opnfv_indicator%</a>
		    </div>
		    
		  </div>
		</div></div>
		`;

	//var replace_search_result_string = function(search_result_string, 
	var search_result = function(string1, string3, result) {
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

		for(index in string_replacement['%tags%']) {
			string1 += '<div class="chip"><a class="a-custom" href="#!">';
			string1 += string_replacement['%tags%'][index]['tag_name'];
			string1 += '</a></div>';
		}

		string3 = string3.replace(/%\w+%/g, function(all) {
   			return string_replacement[all] || all;
		});

		return string1 + string3;
	};



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

	$('#pagination-long').materializePagination({
      align: 'center',
      lastPage:  5,
      firstPage:  1,
      urlParameter: 'page',
      useUrlParameter: true,
      onClickCallback: function(requestedPage){
        	var json_data = {};
        	json_data['tags'] = QueryString()['tags'];
        	json_data['page'] = requestedPage;
  			
  			console.log(json_data);

  			$.ajax({
            	url: '/search_projects_results',
            	type: 'post',
            	dataType: 'json',
            	data: json_data,
            	success: function(data) {
            		//alert(JSON.stringify(data));
            		html_string = '';
            		for(var result in data) {
            			html_string += search_result(search_result_string_1, search_result_string_3, data[result]);
            		}
            		$('#content').html(html_string);
                    //Materialize.toast(data, 3000, 'rounded');
            	},
            	error: function (error) {
                	Materialize.toast('', 3000, 'rounded');
            	}
        	});

        	//window.location.href = '/search_projects?tags=' + parameters['tags'] + '&page=' + requestedPage;
    		//return false;
      }
  	});
	
	/*$('#pagination-long').pagination({
      align: 'center',
      lastPage:  5,
      firstPage:  1,
      //urlParameter: 'page',
      useUrlParameter: false,
      onClickCallback: function(requestedPage){
        	var query_string = {};
  			var query = window.location.search.substring(1);
  			console.log(query);
  			var vars = query.split("&");
  			console.log(vars);
  			vars['page'] = requestedPage;
  			console.log(vars);
  			var parameters = QueryString();
  			
  			console.log(parameters);


        	window.location.href = '/search_projects?tags=' + parameters['tags'];
    		//return false;
      }
      var query_string = {};
  			var query = window.location.search.substring(1);
  			console.log(query);
  			var vars = query.split("&");
  			console.log(vars);
  			vars['page'] = requestedPage;
  			console.log(vars);
  			
  	});*/



});
