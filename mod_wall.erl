%%%   Copyright 2011 EnerNOC, Inc 
%%%
%%%   Licensed under the Apache License, Version 2.0 (the "License");
%%%   you may not use this file except in compliance with the License.
%%%   You may obtain a copy of the License at
%%%
%%%       http://www.apache.org/licenses/LICENSE-2.0
%%%
%%%   Unless required by applicable law or agreed to in writing, software
%%%   distributed under the License is distributed on an "AS IS" BASIS,
%%%   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%%   See the License for the specific language governing permissions and
%%%   limitations under the License.

%%%----------------------------------------------------------------------
%%% File    : mod_wall.erl
%%% Author  : Ed Mackowiak <emackowiak@enernoc.com>
%%% Purpose : flexible IQ filtering by IQ namespace, sender and receiver
%%% Created : June 1st, 2011
%%% Id      : $Id$
%%%----------------------------------------------------------------------

%%%----------------------------------------------------------------------
%%% # Example module config (all options may be ommited to disable extra functionality)
%%%  [{debug, true}, {audit_collector, "test1@emackowiak-mbp.local/Psi+"} ]
%%%    - If debug=true, info messages will be logged to ejabberd.log
%%%    - If audit_collector is specified, a message will be send to the collector whenever a packet is dropped
%%% 
%%% # Example ACL/Access Rule Configuration: (mod_wall uses the acl/access rule style of mod_filter)
%%% 
%%% -Block all disco IQ packets
%%% {access, 'http://jabber.org/protocol/disco#info', [{deny, all}]}
%%%           ^ xmlns (atom) is used as rule name ^ 
%%%
%%% -Block some disco IQ packets
%%% {access, 'http://jabber.org/protocol/disco#info', [{deny, all},
%%%													   {allow, some-acl},
%%%													   {allow, another-acl},  ]}
%%%
%%% -Block some disco IQ packets, depending on their intended recipient
%%% {access, 'http://jabber.org/protocol/disco#info', [{deny, all},
%%%													   {allow, some-acl},
%%%													   {restrict-receivers, all},  ]}
%%%														^^ if a rule is found instead of allow/deny,
%%%														filtering is performed against the packet receiver
%%%														
%%% {access, restrict-receivers, [{deny, denied-receiver-acl}, {allow,all}]}
%%%																^^ guard (important)


-module(mod_wall).
-behavior(gen_mod).
-include("ejabberd.hrl").
-include("jlib.hrl").

-export([start/2, stop/1, on_filter_packet/1, logger/3, apply_rule/1]).

	
start(_Host, _Opts) ->
	ejabberd_hooks:add(filter_packet, global, ?MODULE, on_filter_packet, 50),
	ok.
	
stop(_Host) ->
	ejabberd_hooks:delete(filter_packet, global, ?MODULE, on_filter_packet, 50),
	ok.
	
on_filter_packet(drop) ->
    drop;
    
on_filter_packet({From, To, Packet} = Input) ->
	%%?INFO_MSG("Running filter.  Debug: ~p ", [gen_mod:get_module_opt(global, ?MODULE, debug, false)]),
	
	%returns true if packet type is a set or a get, else false
	ApplyRule = apply_rule( Packet ),
	
	case ApplyRule of
		false -> Input;
		_  -> 
	
			Prefix = get_prefix( Packet ),
			if 
				Prefix == "" -> FilteredNs = get_iq_namespace( Packet );
				true		 -> FilteredNs = get_iq_namespace( Packet, Prefix )
			end,
			
			info("Namespace: ~p ", [FilteredNs]),
			% if the packet isnt an IQ, let it through
			case FilteredNs of
				"" ->
					info("Blank Ns pass through ", []),
					Input;
				_ ->
					FromAccess = match_rule_default_allow(global, list_to_atom(FilteredNs), From),
					case FromAccess of
					deny -> 	
						info("From Filter: Dropping packet: ~p ", [Input]),
						% log the error
						logger( From, To, Packet ),
						%ErrorText = "<error code='403' type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>",
						XmlBody = make_error(Packet, To, From),
						%%	 Trickiness right here:  switched To and From to send back to sender
						ejabberd_router:route(To, From, XmlBody),
						drop;
					allow -> 
						info("From Filter: Pass through: ~p ", [Input]),
						Input;
					ToAccessRule ->
						ToAccess = acl:match_rule(global, ToAccessRule, To),
						
						case ToAccess of
						allow ->
							info("To Filter: Pass through: ~p ", [Input]),
							Input;
						deny ->
							info("To Filter: Dropping packet: ~p ", [Input]),
							% log the error
							logger( From, To, Packet ),
							XmlBody = make_error(Packet, To, From),
							%%	 Trickiness right here:  switched To and From to send back to sender
							ejabberd_router:route(To, From, XmlBody),
							drop
						end
					end
			end		
	end.
	
%%----------------------------------------------------------------------
%% Function: logger/3
%% Purpose: Handle logging of denied packets.
%% Args:    From, To, Packet
%%----------------------------------------------------------------------

logger( From, To, Packet ) ->

	Collector = gen_mod:get_module_opt(global, ?MODULE, audit_collector, none),
	
	case Collector of
	none ->
		none;
	_    ->
		%route the error to the collector
		CollectorJID = jlib:string_to_jid(Collector),
		XmlBody =  {xmlelement, "message",
		   [ {"type", "audit-error"},
			 {"from", "audit-service"},
			 {"to", Collector} 						
		   ],
		   [ 
			 Packet
		   ]
		},
		ejabberd_router:route(From, CollectorJID, XmlBody)
	end.


%%----------------------------------------------------------------------
%% ## UTILITY FUNCTIONS ##
%% The following functions are used to handle xml, log messages, etc
%%----------------------------------------------------------------------


%%----------------------------------------------------------------------
%% Function: make_error/2
%% Purpose: Generate an error (403) IQ.
%% Args:    Packet = xmlelement; the packet to be dropped, required to get ID for response
%% 			To, From = jid; 
%% Returns: An xmlelement ready for routing
%%----------------------------------------------------------------------
make_error(Packet, To, From) ->
	Id = get_iq_id(Packet),
		XmlBody =  {xmlelement, "iq",
		   [ {"type", "error"},
			 {"from", jlib:jid_to_string(To)},
			 {"to", jlib:jid_to_string(From)},
			 {"id", Id }   						
		   ],
		   [ { xmlelement, "error", [{"code", "403"}, {"type", "auth"}], 
				[ { xmlelement, "forbidden", 
					[ { "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas" } ], []
				  } 
				] 
			 } 
		   ]
		},
		XmlBody.


%%----------------------------------------------------------------------
%% Function: get_prefix/1
%% Purpose: Get namespace prefixing of a packet, if present
%% Args:    Packet = xmlelement;
%% Returns: A string containing the namespace prefix, or a blank string if not present
%%----------------------------------------------------------------------
%% example:  <ns0:control />  would return "ns0"
%% example:  <control /> would return ""
get_prefix( Packet ) ->
	
	Name = get_iq_payload_name( Packet ),
	%erlang:display( Name ),
	get_prefix( Name, "" ).
	
get_prefix( [], _ ) ->
	"";

get_prefix( [ Head | Tail ], Prefix ) ->
	case [Head] of
	":" -> % XML is prefixed...
		Prefix;
	_   -> % no prefix found
		get_prefix( Tail, Prefix ++ [Head] )
	end.
		
		
%%----------------------------------------------------------------------
%% Function: get_iq_Id/1
%% Purpose:  Returns the ID of an IQ packet
%% Args:     xmlelement; 
%% Returns:  A string containing the ID if the argument is an IQ, else an empty string
%%----------------------------------------------------------------------
get_iq_id({xmlelement, Name, Attrs, _Els}) when Name == "iq" ->
	xml:get_attr_s("id", Attrs);
	
get_iq_id(_) ->
    "".
		
%%----------------------------------------------------------------------
%% Function: apply_rule/1
%% Purpose:  Decide if ACLs and Access Rules should apply to a packet
%% Args:     xmlelement; 
%% Returns:  Returns the true if the IQ is of type set or get, else false
%%----------------------------------------------------------------------
apply_rule({xmlelement, Name, Attrs, _Els}) when Name == "iq" ->
	
	Type = xml:get_attr_s("type", Attrs),
	
	case Type of
		"set" 	 -> true;
		"get" 	 -> true;
		"error"  -> false;
		"cancel" -> false;
		_		 -> false
	end;
	
apply_rule(_) ->
    false.
		
%%----------------------------------------------------------------------
%% Function: get_iq_namespace/1
%% Purpose:  Gets the namespace of a non-prefixed IQ payload
%% Args:     xmlelement; an IQ
%% Returns:  A string containing the xmlns if present and the packet is an IQ, else an empty string
%%----------------------------------------------------------------------		

get_iq_namespace({xmlelement, Name, _Attrs, Els}) when Name == "iq" ->
    case xml:remove_cdata(Els) of
	[{xmlelement, _Name2, Attrs2, _Els2}] ->
	    xml:get_attr_s("xmlns", Attrs2);
	_ ->
	    ""
    end;
get_iq_namespace(_) ->
    "".


%%----------------------------------------------------------------------
%% Function: get_iq_namespace/2
%% Purpose:  Gets the namespace of a prefixed IQ payload
%% Args:     xmlelement; an IQ
%%			 string; the namespace prefix
%% Returns:  A string containing the non-prefixed xmlns if present and the packet is an IQ, else an empty string
%%----------------------------------------------------------------------
get_iq_namespace({xmlelement, Name, _Attrs, Els}, Prefix) when Name == "iq" ->
    case xml:remove_cdata(Els) of
	[{xmlelement, _Name2, Attrs2, _Els2}] ->
	    xml:get_attr_s("xmlns"++":"++ Prefix, Attrs2);
	_ ->
	    ""
    end;
get_iq_namespace(_, _Prefix) ->
    "".

%%----------------------------------------------------------------------
%% Function: get_iq_payload_name/1
%% Purpose:  Get the tag name of an IQ payload
%% Args:     xmlelement; an IQ
%% Returns:  A string containing the tag name of the payload of the IQ if it exists, else an empty string
%%----------------------------------------------------------------------
get_iq_payload_name({xmlelement, Name, _Attrs, Els}) when Name == "iq" ->
    case xml:remove_cdata(Els) of
	[{xmlelement, Name2, _Attrs2, _Els2}] ->
	    Name2;
	_ ->
	    ""
    end;

get_iq_payload_name(_) ->
    "".

%%----------------------------------------------------------------------
%% Function: match_rule_default_allow/3
%% Purpose:  Look for a matching access rule, but default to 'allow', rather than 'deny'
%% Args:     global;
%%			 Rule; an atomized IQ namespace
%%			 JID; 
%% Returns:  allow | deny
%%----------------------------------------------------------------------
match_rule_default_allow(global, Rule, JID) ->
	case ejabberd_config:get_global_option({access, Rule, global}) of
	% let undefined namespaces through...
	undefined ->
		allow;
	_ ->
		acl:match_rule(global, Rule, JID)
    end.
    
%%----------------------------------------------------------------------
%% Function: info/2
%% Purpose:  Log info messages (if the module 'debug' option is set to true
%% Args:     Str; The format string to be logged
%%			 Arg; A list of elements to be logged
%% Returns:  nothing
%%----------------------------------------------------------------------
info(Str, Arg) ->

	Debug = gen_mod:get_module_opt(global, ?MODULE, debug, false),

	if 
	Debug == true  -> ?INFO_MSG( Str, Arg );
	Debug == false -> false
	end.