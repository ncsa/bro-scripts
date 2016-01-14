##! A bug was reported in OpenSSH versions 5.4 - 7.1 which could
##! expose private date from the client, potentially including private
##! keys. The vulnerability uses a Roaming feature which which was
##! added to OpenSSH clients, but never added to OpenSSH servers.
##!
##! For more information, see:
##!   https://lists.mindrot.org/pipermail/openssh-unix-dev/2016-January/034680.html
##!   http://undeadly.org/cgi?action=article&sid=20160114142733&mode=expanded

@load base/protocols/ssh

module SSH;

export {
	redef enum Notice::Type += {

		## Code was never shipped for servers to support the
		## vulnerable roaming feature.  As such, if a server
		## is seen to be advertising this support, it is
		## very likely malicious.
		Server_Advertises_Malicious_Roaming_Support,

		## A client was observed attempting to resume an SSH
		## connection using the vulnerable roaming feature.
		## This client has been the victim of an attack.
		Client_Sent_Roaming_Resume_Request,
	};
}

event ssh_capabilities(c: connection, cookie: string, capabilities: Capabilities) &priority=-5
	{
	for ( i in capabilities$kex_algorithms )
		{
		if ( capabilities$kex_algorithms[i] == "resume@appgate.com" )
			{
			if ( capabilities$is_server )
				{
				NOTICE([$note=Server_Advertises_Malicious_Roaming_Support,
					$conn=c, $msg=fmt("%s advertises that it supports SSH roaming", c$id$resp_h),
					$identifier=cat(c$id$resp_h)]);
				}
			else
				{
				NOTICE([$note=Client_Sent_Roaming_Resume_Request,
					$conn=c, $msg=fmt("%s attempted to resume a roaming SSH connection", c$id$orig_h),
					$identifier=cat(c$id$orig_h)]);
				}
			}
		}
	}