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

module D = Debug.Debugger(struct let name="extauth_plugin_JIT" end)
open D

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

let user_friendly_error_msg = "The Active Directory Plug-in could not complete the command. Additional information in the XenServer log."

open Pervasiveext


let likewise_common ?stdin_string:(stdin_string="") params_list likewise_cmd =

	(* SECURITY: params_list is untrusted external data. Therefore, we must be careful against *)
	(* the user sending arbitrary injection commands by escaping the likewise cmd parameters. *)
	(* In order to avoid any escaping or injection exploiting the shell, we call Unix.execvp directly (via create_process, see unix.ml), *)
	(* instead of using the shell to interpret the parameters and execute the likewise cmd. *)
	
	let debug_cmd = (likewise_cmd^" "^(List.fold_right (fun p pp->"\""^p^"\" "^pp) params_list "")) in

	(* stuff to clean up on the way out of the function: *)
	let fds_to_close = ref [] in
	let files_to_unlink = ref [] in
	(* take care to close an fd only once *)
	let close_fd fd = 
	  if List.mem fd !fds_to_close then begin
	    Unix.close fd;
	    fds_to_close := List.filter (fun x -> x <> fd) !fds_to_close
	  end in
	(* take care to unlink a file only once *)
	let unlink_file filename = 
	  if List.mem filename !files_to_unlink then begin
	    Unix.unlink filename;
	    files_to_unlink := List.filter (fun x -> x <> filename) !files_to_unlink
	  end in
	(* guarantee to release all resources (files, fds) *)
	let finalize () = 
	  List.iter close_fd !fds_to_close;
	  List.iter unlink_file !files_to_unlink in
	let finally_finalize f = finally f finalize in
	finally_finalize 
	  (fun () ->
	(* creates pipes between xapi and likewise process *)
	let (in_readme, in_writeme) = Unix.pipe () in
	fds_to_close := in_readme :: in_writeme :: !fds_to_close;
	let out_tmpfile = Filename.temp_file "lw" ".out" in
	files_to_unlink := out_tmpfile :: !files_to_unlink;
	let err_tmpfile = Filename.temp_file "lw" ".err" in
	files_to_unlink := err_tmpfile :: !files_to_unlink;
	let out_writeme = Unix.openfile out_tmpfile [ Unix.O_WRONLY] 0o0 in
	fds_to_close := out_writeme :: !fds_to_close;
	let err_writeme = Unix.openfile err_tmpfile [ Unix.O_WRONLY] 0o0 in
	fds_to_close := err_writeme :: !fds_to_close;

	let pid = Forkhelpers.safe_close_and_exec (Some in_readme) (Some out_writeme) (Some err_writeme) [] likewise_cmd params_list in

	finally
	  (fun () ->
	        debug "Created process pid %s for cmd %s" (Forkhelpers.string_of_pidty pid) debug_cmd;
	  	(* Insert this delay to reproduce the cannot write to stdin bug: 
		   Thread.delay 5.; *)
	   	(* WARNING: we don't close the in_readme because otherwise in the case where the likewise 
		   binary doesn't expect any input there is a race between it finishing (and closing the last
		   reference to the in_readme) and us attempting to write to in_writeme. If likewise wins the
		   race then our write will fail with EPIPE (Unix.error 31 in ocamlese). If we keep a reference
		   to in_readme then our write of "\n" will succeed.

		   An alternative fix would be to not write anything when stdin_string = "" *)

		(* push stdin_string to recently created process' STDIN *)
		begin 
		(* usually, STDIN contains some sensitive data such as passwords that we do not want showing up in ps *)
		(* or in the debug log via debug_cmd *)
		try
			let stdin_string = stdin_string ^ "\n" in (*HACK:without \n, the likewise scripts don't return!*)
			let (_: int) = Unix.write in_writeme stdin_string 0 (String.length stdin_string) in
			close_fd in_writeme; (* we need to close stdin, otherwise the unix cmd waits forever *)
		with e -> begin
			(* in_string is usually the password or other sensitive param, so never write it to debug or exn *)
			debug "Error writing to stdin for cmd %s: %s" debug_cmd (ExnHelper.string_of_exn e);
			raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,ExnHelper.string_of_exn e))
		end
		end;
	  )
	  (fun () -> Forkhelpers.waitpid pid);

	(* <-- at this point the process has quit and left us its output in temporary files *)

	(* we parse the likewise cmd's STDOUT *)
	let result =
	try 
		(* we read STDERR, just for completeness, but do not expect anything here *)
		(try
			let err_readme = Unix.openfile err_tmpfile [ Unix.O_RDONLY ] 0o0 in
			fds_to_close := err_readme :: !fds_to_close;

			let err_readme_c = (Unix.in_channel_of_descr err_readme) in
			let err_result = Parse_likewise.of_channel err_readme_c in
			(* parse_likewise will raise a parse_failure exception here if something unusual is returned in STDERR *)
			(* parse_likewise will raise an End_of_file exception here if nothing is returned in STDERR *)
			
			(* we should never reach this point. *)
			let msg = 
				(Printf.sprintf "Likewise returned success/failure in STDERR for cmd %s: %s" debug_cmd
					(match err_result with 
						| Parse_likewise.Success ls-> "SUCCESS"^(List.fold_left (fun a b -> " "^a^" "^b) "" (List.map (fun (k,v)->k^"="^v) ls))
						| Parse_likewise.Failure (code,err)-> Printf.sprintf "FAILURE %i: %s" code err
					)
				)
			in
			debug "%s" msg;
			raise (Parse_likewise.Parse_failure (msg,"IN STDERR"))
		with
			| End_of_file ->  () (* OK, we expect no STDERR output, therefore an EOF is expected *)
			| e -> (* unexpected error returned by likewise when reading STDERR *)
				begin
					debug "Likewise returned an error in STDERR: %s" (ExnHelper.string_of_exn e);
					raise e (* this should be caught by the parse_failure/unknown_error handlers below *)
				end
		);
		(* we read STDOUT *)
		let out_readme = Unix.openfile out_tmpfile [ Unix.O_RDONLY ] 0o0 in
		fds_to_close := out_readme :: !fds_to_close;

		let out_readme_c = (Unix.in_channel_of_descr out_readme) in
		let out_list = Parse_likewise.of_channel out_readme_c in
		out_list
	with 
		| Parse_likewise.Parse_failure (param,err) ->
			let msg = (Printf.sprintf "Parse_likewise failure for returned value %s: %s" param err) in
			debug "Error likewise for cmd %s: %s" debug_cmd msg;
			(* CA-27772: return user-friendly error messages when Likewise crashes *)
			let msg = user_friendly_error_msg in
			raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,msg))
		| e -> (* unknown error *)
		begin
			debug "Parse_likewise error for cmd %s: %s" debug_cmd (ExnHelper.string_of_exn e);
			(* CA-27772: return user-friendly error messages when Likewise crashes *)
			let msg = user_friendly_error_msg in
			raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,msg (*(ExnHelper.string_of_exn e)*)))
		end
	in


	(* finally, we analyze the results *)
	begin
	match result with
		| Parse_likewise.Success attrs ->
			attrs (* OK, return the whole output list *)
		| Parse_likewise.Failure (code,errmsg) -> begin
			debug "Likewise raised an error for cmd %s: (%i) %s" debug_cmd code errmsg;
			match code with
				| 40008    (* no such user *)
				| 40012    (* no such group *)
				| 40071    (* no such user, group or domain object *)
					-> raise Not_found (*Subject_cannot_be_resolved*)

				| 40047    (* empty password, The call to kerberos 5 failed *)
				| 40022    (* The password is incorrect for the given username *)
				| 40056    (* The user account is disabled *)
				| 40017    (* The authentication request could not be handled *)
					-> raise (Auth_signature.Auth_failure errmsg)

				| 524334
					-> raise (Auth_signature.Auth_service_error (Auth_signature.E_INVALID_OU,errmsg))
				| 524326    (* error joining AD domain *)
				| 524359 -> (* error joining AD domain *)
					raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,errmsg))

				| 40118 (* lsass server not responding *)
				| _ ->  (* general Likewise error *)
					raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,(Printf.sprintf "(%i) %s" code errmsg)))
		end
	end	  
)

let get_joined_domain_name () =
	Server_helpers.exec_with_new_task "obtaining joined-domain name"
		(fun __context -> 
			let host = Helpers.get_localhost ~__context in
			(* the service_name always contains the domain name provided during domain-join *)
			Db.Host.get_external_auth_service_name ~__context ~self:host;
		)

(* CP-842: when resolving AD usernames, make joined-domain prefix optional *)
let get_full_subject_name ?(use_nt_format=true) subject_name = (* CA-27744: always use NT-style names by default *)
	try
		(* tests if the UPN account name separator @ is present in subject name *)
		ignore(String.index subject_name '@'); 
		(* we only reach this point if the separator @ is present in subject_name *)
		(* nothing to do, we assume that subject_name already contains the domain name after @ *)
		subject_name
	with Not_found -> begin (* if no UPN username separator @ was found *)
		try
			(* tests if the NT account name separator \ is present in subject name *)
			ignore(String.index subject_name '\\');
			(* we only reach this point if the separator \ is present in subject_name *)
			(* nothing to do, we assume that subject_name already contains the domain name before \ *)
			subject_name
		with Not_found -> begin (* if neither the UPN separator @ nor the NT username separator \ was found *)
			if use_nt_format then begin (* the default: NT names is unique, whereas UPN ones are not (CA-27744) *)
			(* we prepend the joined-domain name to the subjectname as an NT name: <domain.com>\<subjectname> *) 
			(get_joined_domain_name ()) ^ "\\" ^ subject_name
			(* obs: (1) likewise accepts a fully qualified domain name <domain.com> with both formats and *)
			(*      (2) some likewise commands accept only the NT-format, such as lw-find-group-by-name *)
			end 
			else begin (* UPN format not the default format (CA-27744) *)
			(* we append the joined-domain name to the subjectname as a UPN name: <subjectname>@<domain.com> *) 
			subject_name ^"@"^(get_joined_domain_name ())
			end
		end
	end

(* Converts from UPN format (user@domain.com) to legacy NT format (domain.com\user) *)
(* This function is a workaround to use lw-find-group-by-name, which requires nt-format names) *)
(* For anything else, use the original UPN name *)
let convert_upn_to_nt_username subject_name =
	try
		(* test if the UPN account name separator @ is present in subject name *)
		let i = String.index subject_name '@' in 
		(* we only reach this point if the separator @ is present in subject_name *)
		(* when @ is present, we need to convert the UPN name to NT format *)
		let user = String.sub subject_name 0 i in
		let domain = String.sub subject_name (i+1) ((String.length subject_name) - i - 1) in
		domain ^ "\\" ^ user
	with Not_found -> begin (* if no UPN username separator @ was found *)
		(* nothing to do in this case *)
		subject_name
	end

let likewise_get_all_byid subject_id =

	let subject_attrs = likewise_common ["--minimal";subject_id] "/opt/likewise/bin/lw-find-by-sid" in
	subject_attrs (* OK, return the whole output list *)

let likewise_get_group_sids_byname _subject_name =
	let subject_name = get_full_subject_name _subject_name in (* append domain if necessary *)

	let subject_attrs = likewise_common ["--minimal";subject_name] "/opt/likewise/bin/lw-list-groups" in
	(* returns all sids in the result *)
	List.map (fun (n,v)->v) (List.filter (fun (n,v)->n="Sid") subject_attrs)

let likewise_get_sid_bygid gid =
	
	let subject_attrs = likewise_common ["--minimal";gid] "/opt/likewise/bin/lw-find-group-by-id" in
	(* lw-find-group-by-id returns several lines. We only need the SID *)
	if List.mem_assoc "SID" subject_attrs then List.assoc "SID" subject_attrs (* OK, return SID *)
	else begin (*no SID value returned*)
		(* this should not have happend, likewise didn't return an SID field!! *)
		let msg = (Printf.sprintf "Likewise didn't return an SID field for gid %s" gid) in
		debug "Error likewise_get_sid_bygid for gid %s: %s" gid msg;
		raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,msg)) (* general Likewise error *)
	end

let likewise_get_sid_byname _subject_name cmd = 
	let subject_name = get_full_subject_name _subject_name in (* append domain if necessary *)

	let subject_attrs = likewise_common ["--minimal";subject_name] cmd in
	(* lw-find-user-by-name returns several lines. We ony need the SID *)
	if List.mem_assoc "SID" subject_attrs then List.assoc "SID" subject_attrs (* OK, return SID *)
	else begin (*no SID value returned*)
		(* this should not have happend, likewise didn't return an SID field!! *)
		let msg = (Printf.sprintf "Likewise didn't return an SID field for user %s" subject_name) in
		debug "Error likewise_get_sid_byname for subject name %s: %s" subject_name msg;
		raise (Auth_signature.Auth_service_error (Auth_signature.E_GENERIC,msg)) (* general Likewise error *)
	end

(* subject_id get_subject_identifier(string subject_name)

	Takes a subject_name (as may be entered into the XenCenter UI when defining subjects -- 
*)
let get_subject_identifier _subject_name = 
	"JIT/" ^ _subject_name

	
(* subject_id Authenticate_username_password(string username, string password)

	Takes a username and password, and tries to authenticate against an already configured 
	auth service (see XenAPI requirements Wiki page for details of how auth service configuration 
	takes place and the appropriate vlaues are stored within the XenServer Metadata). 
	If authentication is successful then a subject_id is returned representing the account 
	corresponding to the supplied credentials (where the subject_id is in a namespace managed by 
	the auth module/service itself -- e.g. maybe a SID or something in the AD case). 
	Raises auth_failure if authentication is not successful
*)

(* subject_id Authenticate_ticket(string ticket)

	As above but uses a ticket as credentials (i.e. for single sign-on)
*)
	(* not implemented now, not needed for our tests, only for a *)
	(* future single sign-on feature *)
let authenticate_ticket tgt = 
	failwith "extauth_plugin authenticate_ticket not implemented"
	 
let with_connection ip port f =
	let inet_addr = Unix.inet_addr_of_string ip in
	let addr = Unix.ADDR_INET(inet_addr, port) in
	let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
	Unix.connect s addr;
	Unixext.set_tcp_nodelay s true;
	finally
		(fun () -> f s)
		(fun () -> Unix.close s)

let with_stunnel ip port =
	fun f ->
			let s = Stunnel.connect ~use_fork_exec_helper:false ~extended_diagnosis:false ip port in
			let fd = s.Stunnel.fd in
			finally
					(fun () -> f fd)
					(fun () -> Stunnel.disconnect s)


let sendrequest_plain str s =
	Http_client.rpc s (Http.Request.make ~frame:false ~version:"1.1" ~keep_alive:false ~user_agent:"test_agent" ~auth:(Http.Basic("", "")) ~body:str Http.Post "/MessageService")
	(fun response s ->
		match response.Http.Response.content_length with
			| Some l ->
				Unixext.really_read_string s (Int64.to_int l) in
			| None -> failwith "Need a content length"
	)

let authenticate_cert tgt = 
	Server_helpers.exec_with_new_task "authenticate "
    (fun __context ->
        let host = Helpers.get_localhost ~__context in
        let conf = Db.Host.get_external_auth_configuration ~__context ~self:host in
        let ip = List.assoc "ip" conf in
        let port = List.assoc "port" conf in
        with_stunnel ip (int_of_string port) (sendrequest_plain tgt)
    )


let authenticate_username_password _username password = 
	authenticate_cert "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" ^
					  "<message>\r\n"^
					  "<head>\r\n"^
					  "<version>1.0</version>\r\r"^
					  "<serviceType>OriginalService</serviceType>\r\n"^
					  "</head>\r\n"^
					  "<appId>testId</appId>\r\n"^
					  "</body>\r\n"^
					  "</message>\r\n"

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
	let subject_name = String.sub subject_identifier 3 ((String.length subject_identifier) - 3) in
	[	("subject-name", subject_name);
		("subject-sid", subject_identifier);
		("subject-is-group", "false");
	]


(* (string list) query_group_membership(string subject_identifier)

	Takes a subject_identifier and returns its group membership (i.e. a list of subject 
	identifiers of the groups that the subject passed in belongs to). The set of groups returned 
	_must_ be transitively closed wrt the is_member_of relation if the external directory service 
	supports nested groups (as AD does for example)
*)
let query_group_membership subject_identifier = 

	let subject_info = query_subject_information subject_identifier in
	
	if (List.assoc "subject-is-group" subject_info)="true" (* this field is always present *)
	then (* subject is a group, so get_group_sids_byname will not work because likewise's lw-list-groups *)
	     (* doesnt work if a group name is given as input *)
	     (* FIXME: default action for groups until workaround is found: return an empty list of membership groups *)
		[]
	else (* subject is a user, lw-list-groups and therefore get_group_sids_byname work fine *)
	let subject_name = List.assoc "subject-name" subject_info in (* CA-27744: always use NT-style names *)

	let subject_sid_membership_list = likewise_get_group_sids_byname subject_name in
	debug "Resolved %i group sids for subject %s (%s): %s"
		(List.length subject_sid_membership_list)
		subject_name
		subject_identifier
		(List.fold_left (fun p pp->if p="" then pp else p^","^pp) "" subject_sid_membership_list);
	subject_sid_membership_list

(* converts from domain.com\user to user@domain.com, in case domain.com is present in the subject_name *)
let convert_nt_to_upn_username subject_name =
	try
		(* test if the NT account name separator \ is present in subject name *)
		let i = String.index subject_name '\\' in 
		(* we only reach this point if the separator \ is present in subject_name *)
		(* when \ is present, we need to convert the NT name to UPN format *)
		let domain = String.sub subject_name 0 i in
		let user = String.sub subject_name (i+1) ((String.length subject_name) - i - 1) in
		user ^ "@" ^ domain
		
	with Not_found -> begin (* if no NT username separator \ was found *)
		(* nothing to do in this case *)
		subject_name
	end

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
	       Auth_signature.get_subject_identifier = get_subject_identifier;
	       Auth_signature.query_subject_information = query_subject_information;
	       Auth_signature.query_group_membership = query_group_membership;
	       Auth_signature.on_enable = on_enable;
	       Auth_signature.on_disable = on_disable;
	       Auth_signature.on_xapi_initialize = on_xapi_initialize;
	       Auth_signature.on_xapi_exit = on_xapi_exit}

end
  
