(*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)
(**
 * @group Access Control
 *)

open Xml
module D = Debug.Debugger(struct let name="extauth_plugin_JIT" end)
open D
open Auth_signature
open Stringext

module AuthJIT : Auth_signature.AUTH_MODULE =
struct

(* 
 * External Authentication Plugin component
 * using JIT cert as a backend
 *
*)

(** has_substr str sub returns true if sub is a substring of str. Simple, naive, slow. *)
let has_substr str sub =
  if String.length sub > String.length str then false else
    begin
      let result=ref false in
      for start = 0 to (String.length str) - (String.length sub) do
	if String.sub str start (String.length sub) = sub then result := true
      done;
      !result
    end

open Pervasiveext

let get_subject_identifier _subject_name = 
	_subject_name
	
let parse_cert_result = function
	| Element ("message", _, [Element ("head", _, headchildren); Element ("body", _, bodychildren)] ) ->
		let rec get_messagestate = function
			| Element ("messageState", _, (PCData head)::_) :: tail -> head
			| _::tail -> get_messagestate tail
			| [] -> ""
		in
		let messagestate = get_messagestate headchildren in
		if messagestate = "true" then
			raise (Auth_signature.Auth_failure "Authenticate failed, the messagestate is true")
		else
		let process_body = function
			| Element ("authResultSet", _, _)::Element ("attributes", _, attrs)::_
			| Element ("authResultSet", _, _)::_::Element ("attributes", _, attrs)::_ ->
				let rec find_attr name = function
					| Element ("attr", [("name", value); ("namespace", namespace)], (PCData head)::_) :: tail -> 
						let key = String.sub value ((String.length value) - (String.length name)) (String.length name) in 
						if key = name then head else find_attr name tail
					|[] -> ""
					| _ -> raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,"Can't parse the certificate xml attributes"))
				in 
				let subjectdn = find_attr "SubjectDN" attrs in
				let sli = List.map 
							(fun x -> String.sub x 0 (String.index x '='), String.sub x (String.index x '=' + 1) (String.length x - String.index x '=' - 1)) 
							(String.split ',' subjectdn) 
				in
				let username = List.assoc "CN" sli in 
				if List.mem_assoc "OU" sli then
					let group = List.assoc "OU" sli in
					[username;group]
				else
					[username]
			| _ ->
				raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,"Can't parse the certificate xml body"))
		in
		let body = process_body bodychildren in
		body
				
	| _ -> raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,"Can't parse the certificate xml"))

let parse_original_result = function
	| Element ("message", _, [Element ("head", _, _); Element ("body", _, Element ("original", _, (PCData originalcode)::_) :: _)] ) -> originalcode
	| Element ("message", _, Element ("head", _, _)::[]) -> raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,"The original code is empty"))
	| _ -> raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,"Can't parse the original xml"))
		
		
let authenticate_ticket tgt = 
	failwith "extauth_plugin authenticate_ticket not implemented"
	 
let with_connection ip port f =
	let inet_addr = Unix.inet_addr_of_string ip in
	let addr = Unix.ADDR_INET(inet_addr, port) in
	let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
	Unix.connect s addr;
	Unixext.set_tcp_nodelay s true;
	finally (fun () -> f s)
		(fun () -> Unix.close s)

let with_stunnel ip port =
	fun f ->
			let s = Stunnel.connect ~use_fork_exec_helper:false ~extended_diagnosis:false ip port in
			let fd = s.Stunnel.fd in
			finally
					(fun () -> f fd)
					(fun () -> Stunnel.disconnect s)


let sendrequest_plain str s =
	Http_client.rpc s (Http.Request.make ~frame:false ~version:"1.1" ~keep_alive:false ~user_agent:"test_agent" ~body:str Http.Post "/MessageService")
	(fun response s ->
		match response.Http.Response.content_length with
			| Some l ->
				Unixext.really_read_string s (Int64.to_int l)
			| None -> failwith "Need a content length"
	)

let http_post str =
	let ip, port = Server_helpers.exec_with_new_task "obtain the ip and port of authenticate gateway"
    (fun __context ->
		let host = Helpers.get_localhost ~__context in
		let conf = Db.Host.get_external_auth_configuration ~__context ~self:host in
		let ip = List.assoc "ip" conf in
		let port = List.assoc "port" conf in
		(ip,port)
    )
	in
	let http_post = Filename.concat Fhs.libexecdir "http_post" in
	let url = Printf.sprintf "http://%s:%s/MessageService" ip port in
	let output =
		(try
			let output, stderr = Forkhelpers.execute_command_get_output http_post [url; str] in
			debug "execute %s: stdout=[%s],stderr=[%s]" http_post (Stringext.String.replace "\n" ";" output) (Stringext.String.replace "\n" ";" stderr);
			output
		with e-> (
				  raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,(ExnHelper.string_of_exn e)))
				 )
		);
	in
	Xml.parse_string output

let authenticate_cert cert = 
	parse_cert_result (http_post cert)


	(***
	Server_helpers.exec_with_new_task "authenticate "
    (fun __context ->
		let host = Helpers.get_localhost ~__context in
		let conf = Db.Host.get_external_auth_configuration ~__context ~self:host in
		let ip = List.assoc "ip" conf in
		let port = List.assoc "port" conf in
		let cert_result = with_stunnel ip (int_of_string port) (sendrequest_plain tgt) in
		let cert_xml = Xml.parse_string cert_result in
		parse_cert_result cert_xml
    )

	*)
let get_original () =
	parse_original_result (http_post 
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<message>
	<head>
		<version>1.0</version>
		<serviceType>OriginalService</serviceType>
	</head>
	<body>
		<appId>vGate</appId>
	</body>
</message>")



let authenticate_username_password _username password = 
	failwith "authenticate_username_password is not implement"

	(**
	Server_helpers.exec_with_new_task "authenticate "
    (fun __context ->
		let body = Printf.sprintf "<?xml version=\"1.0\" encoding=\"UTF-8\"?><message><head><version>1.0</version><serviceType>%s</serviceType></head><body><appId>%s</appId></body></message>" "OriginalService" "vGate"  in
        let host = Helpers.get_localhost ~__context in
        let conf = Db.Host.get_external_auth_configuration ~__context ~self:host in
        let ip = List.assoc "ip" conf in
        let port = List.assoc "port" conf in
		let open Xmlrpc_client in
		(**
		let url = Http.Url.of_string (Printf.sprintf "http://%s:%s" ip port) in
		let transport = Xmlrpc_client.transport_of_url url in
		*)
		let transport = SSL(SSL.make (), ip, int_of_string port) in
		let request = Http.Request.make ~user_agent:"xapi" ~keep_alive:false ~body ~headers:["Host", ip] ~content_type:"application/xml" ~host:ip
			Http.Post "/MessageService" in
		with_transport transport 
			(with_http request
				(fun (response, s) ->
					match response.Http.Response.content_length with
						| Some l ->
							Unixext.really_read_string s (Int64.to_int l)
						| None -> failwith "Need a content length"
				)
			)
		
    )
	*)


	(**  This is use thirdparty netclient
	Server_helpers.exec_with_new_task "authenticate "
    (fun __context ->
		let body = Printf.sprintf "<?xml version=\"1.0\" encoding=\"UTF-8\"?><message><head><version>1.0</version><serviceType>%s</serviceType></head><appId>%s</appId></body></message>" "OriginalService" "testApp"  in
        let host = Helpers.get_localhost ~__context in
        let conf = Db.Host.get_external_auth_configuration ~__context ~self:host in
        let ip = List.assoc "ip" conf in
        let port = List.assoc "port" conf in
		let open Http_client in
		let m = new post_raw (Printf.sprintf "http://%s:%s/MessageService" ip port) body in 
		m # get_resp_body()
		
    )
	*)
	

(* ((string*string) list) query_subject_information(string subject_identifier)

	Takes a subject_identifier and returns the user record from the directory service as 
	key/value pairs. In the returned string*string map, there _must_ be a key called 
	subject_name that refers to the name of the account (e.g. the user or group name as may 
	be displayed in XenCenter). There is no other requirements to include fields from the user 
	record -- initially qI'd imagine that we wouldn't bother adding anything else here, but 
	it's a string*string list anyway for possible future expansion. 
	Raises Not_found (*Subject_cannot_be_resolved*) if subject_id cannot be resolved by external auth service
*)
let query_subject_information subject_identifier = 
	[	("subject-name", subject_identifier);
		("subject-sid", subject_identifier);
		("subject-is-group", "false");
		("subject-account-disabled", "false");
		("subject-account-expired", "false"); 
		("subject-account-locked", "false"); 
		("subject-password-expired", "false") 
	]


(* (string list) query_group_membership(string subject_identifier)

	Takes a subject_identifier and returns its group membership (i.e. a list of subject 
	identifiers of the groups that the subject passed in belongs to). The set of groups returned 
	_must_ be transitively closed wrt the is_member_of relation if the external directory service 
	supports nested groups (as AD does for example)
*)
let query_group_membership subject_identifier = 
	[]

(* unit on_enable(((string*string) list) config_params)

	Called internally by xapi _on each host_ when a client enables an external auth service for the 
	pool via the XenAPI [see AD integration wiki page]. The config_params here are the ones passed 
	by the client as part of the corresponding XenAPI call.
	On receiving this hook, the auth module should:
	(i) do whatever it needs to do (if anything) to register with the external auth/directory 
		service [using the config params supplied to get access]
	(ii) Write the config_params that it needs to store persistently in the XenServer metadata 
		into the Pool.external_auth_configuration field. [Note - the rationale for making the plugin 
		write the config params it needs long-term into the XenServer metadata itself is so it can 
		explicitly filter any one-time credentials [like AD username/password for example] that it 
		does not need long-term.]
*)
let on_enable config_params =

	if not ( (List.mem_assoc "ip" config_params)
			&& (List.mem_assoc "port" config_params)
		) 
	then begin
		raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,"enable requires two config params: ip and port."))
	end
	else
	
	let ip = List.assoc "ip" config_params in
	let port = List.assoc "port" config_params in
	let (ou_conf,ou_params) = if (List.mem_assoc "ou" config_params) then let ou=(List.assoc "ou" config_params) in ([("ou",ou)],["--ou";ou]) else ([],[]) in
	(*
	let status = Sys.command ("ping -c 1 "^ ip) in
	debug "The ping result from %s is: %s" ip (string_of_int status);
	if status <> 0
	then begin
		raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC, "The ip is not reachable"))
	end
	else
	*)
	
	try
		let client_sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
		let inet_addr = Unix.inet_addr_of_string ip in
		Unix.connect client_sock (Unix.ADDR_INET (inet_addr, int_of_string port));
		Unix.shutdown client_sock SHUTDOWN_ALL;
		let extauthconf = [
			("ip", ip);
			("port", port)
		] @ ou_conf in
		Server_helpers.exec_with_new_task "storing external_auth_configuration"
			(fun __context -> 
				let host = Helpers.get_localhost ~__context in
				Db.Host.set_external_auth_configuration ~__context ~self:host ~value:extauthconf;
				debug "added external_auth_configuration for host %s" (Db.Host.get_name_label ~__context ~self:host)
			);
		() (* OK, return unit*)

	with (*ERROR, The cert service is not available*)
	|Auth_signature.Auth_service_error (errtag,errmsg) as e ->
		(*errors in stdout, let's bubble them up, making them as user-friendly as possible *)
		debug "Error enabling external authentication for ip %s : %s" ip errmsg;
		if has_substr errmsg "63" 
		then begin 
			raise (Auth_signature.Auth_service_error (Auth_signature.E_DENIED,"The port is not correct"))
		end
		else begin (* general error *)
			raise e
		end

(* unit on_disable()

	Called internally by xapi _on each host_ when a client disables an auth service via the XenAPI. 
	The hook will be called _before_ the Pool configuration fields relating to the external-auth 
	service are cleared (i.e. so you can access the config params you need from the pool metadata 
	within the body of the on_disable method)
*)
let on_disable config_params =

	(* remove persistently the relevant config_params in the host.external_auth_configuration field *)
	Server_helpers.exec_with_new_task "removing external_auth_configuration"
		(fun __context -> 
			let host = Helpers.get_localhost ~__context in
			Db.Host.set_external_auth_configuration ~__context ~self:host ~value:[];
			debug "removed external_auth_configuration for host %s" (Db.Host.get_name_label ~__context ~self:host)
		);
        ()		
    

(* unit on_xapi_initialize(bool system_boot)

	Called internally by xapi whenever it starts up. The system_boot flag is true iff xapi is 
	starting for the first time after a host boot
*)
let on_xapi_initialize system_boot =

	()

(* unit on_xapi_exit()

	Called internally when xapi is doing a clean exit.
*)
let on_xapi_exit () =
	(* nothing to do here in this unix plugin *) 
	
	(* in the ldap plugin, we should remove the tgt ticket in /tmp/krb5cc_0 *)
	()

(* Implement the single value required for the module signature *)
let methods = {Auth_signature.authenticate_username_password = authenticate_username_password;
	       Auth_signature.authenticate_ticket = authenticate_ticket;
	       Auth_signature.authenticate_cert = authenticate_cert;
	       Auth_signature.get_original = get_original;
	       Auth_signature.get_subject_identifier = get_subject_identifier;
	       Auth_signature.query_subject_information = query_subject_information;
	       Auth_signature.query_group_membership = query_group_membership;
	       Auth_signature.on_enable = on_enable;
	       Auth_signature.on_disable = on_disable;
	       Auth_signature.on_xapi_initialize = on_xapi_initialize;
	       Auth_signature.on_xapi_exit = on_xapi_exit}

end
  
