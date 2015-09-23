<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!-- 
 Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 -->
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>WAYF</title>
<script type="text/javascript" src="js/jquery-1.11.3.js"></script>
<script type="text/javascript">

$(document).ready(function() {

	loadList($('#loadIdP').val());
	
	if($('#ListSelect option').size() == 1 || $('#isPassive').val()=='true')
		$('#formWAYF').submit();

	var cookieVal = getCookie('wayfChoice');
	if(cookieVal!=null){
		$('#ListSelect').val(cookieVal);
		document.getElementById('memorizzaChk').checked = true;
		if($('#spEntityId').val()!=''){
			$('#formWAYF').submit();
		}
	}
});

function loadList(isIdPList){
	if(isIdPList=='true')
		op = 'getIdPList';
	else
		op =  'getWAYFList';
	
	$.ajax({
		url: './WAYF',
		type: 'POST',
		data: ({op: op, spEntityId:$('#spEntityId').val()}),
		async: false,
		success: function(data, stato){
			var status = data.split('\n');			
			if(status[0] == 'OK'){
				$('#ListSelect').html('');
				for(var i=1;i<status.length;i++){
					var rawArray = status[i].split(',');
					var id = rawArray[1];
					var name = (rawArray[0]=='default')? rawArray[2] : rawArray[0] + ' ' +  rawArray[2];
					if(!(isIdPList=='true'))
						name = rawArray[0]
					var imgUrl = rawArray[3];
					$('#ListSelect').append('<option value="'+id+'" '+(i==1?'selected="selected"':'')+'>'+name+'</option>');
				}
			} else {
				alert('Errore: '+status[1]);
			}
		},
		error: function (richiesta, stato, errori) {alert('Errore nel caricamento della lista');}
	});
}

function handleMemorizza(){
	if(document.getElementById('memorizzaChk').checked){
		document.cookie = 'wayfChoice='+$('#ListSelect option:selected').val();
	}else{
		document.cookie = 'wayfChoice=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
	}
}

function getCookie(name) {
	var value = "; " + document.cookie;
	var parts = value.split("; " + name + "=");
	if (parts.length == 2) return parts.pop().split(";").shift();
}
</script>
<style type="text/css">
html, body {
    height: 100%;
}
#loginDiv{
	position:fixed;
	
	margin:-100px 0 0 -150px;
	left:50%;
	top:50%;
	
	text-align:center;
	padding: 0px 20px;
	border-radius:25px;
	background:#D5E5F2;
	font-family : Verdana, Arial, Helvetica, sans-serif;
	font-size:15px;
}
</style>
</head>
<body>
	<div id="loginDiv">
		<br/>Scegliere l'ente con cui autenticarsi<br/><br/>
		<form id="formWAYF" action="./WAYF" method="post">
			<select id="ListSelect" name="ListSelect" onchange='handleMemorizza();'></select>
			<input type="hidden" id="spEntityId" name="spEntityId" value="<%=(request.getParameter("entityID")!=null)?request.getParameter("entityID"):""%>"/>
			<input type="hidden" id="spReturnUrl" name="spReturnUrl" value="<%=(request.getParameter("return")!=null)?request.getParameter("return"):""%>"/>
			<input type="hidden" id="spReturnParamName" name="spReturnParamName" value="<%=(request.getParameter("returnIDParam")!=null)?request.getParameter("returnIDParam"):"entityID"%>"/>
			<input type="hidden" id="loadIdP" name="loadIdP" value="<%=(request.getParameter("loadIdP")!=null)?request.getParameter("loadIdP"):"true"%>"/>
			<input type="hidden" id="isPassive" name="isPassive" value="<%=(request.getParameter("isPassive")!=null)?request.getParameter("isPassive"):"false"%>"/>
			
			<input type="submit" value="go"/>
		</form>
		<br/>
		<label>Memorizza scelta <input id="memorizzaChk" type="checkbox" onclick='handleMemorizza();'/></label>
		<br/>
		<br/>
	</div>
</body>
</html>