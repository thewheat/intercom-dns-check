require 'sinatra'
require 'resolv'
require 'uri'
require 'dnsruby'
require 'public_suffix'
include Dnsruby


class DnsCheck
  attr_reader :host
  def initialize(host)
    @host = host
  end

  def a
    @a ||= Resolv::DNS.new.getresources(host, Resolv::DNS::Resource::IN::A)
  end

  def a?
    a.any?
  end

  def mx
    @mx ||= Resolv::DNS.new.getresources(host, Resolv::DNS::Resource::IN::MX)
  end

  def mx?
    mx.any?
  end

  def ns
    @ns ||= Resolv::DNS.new.getresources(host, Resolv::DNS::Resource::IN::NS)
  end

  def ns?
    ns.any?
  end
end


def get_intercom_dkim_base
	return "intercom._domainkey"	
end

def get_intercom_dkim(domain)
	return "#{get_intercom_dkim_base}.#{domain}"	
end
def get_intercom_dkim_double_domain(domain)
	return "#{get_intercom_dkim_base}.#{domain}.#{domain}"	
end
def get_cname(url)
	begin
	  r = Resolv::DNS.open do |dns|
	    dns.getresource(url, Resolv::DNS::Resource::IN::CNAME)
	  end
	  puts "CNAME: #{r.inspect}"
	  return r.name.to_s
	rescue Resolv::ResolvError => e
	  # handle error
	end	
end
def txt_has_cname(txts)

	txts.each{|txt|
		return true if txt[:type].to_s.downcase.strip == "cname"
	} if txts && txts.count > 0
	return false
end
def txt_has_txt(txts)
	txts.each{|txt|
		return true if txt[:type].to_s.downcase.strip == "txt"
	} if txts && txts.count > 0
	return false
end
def get_txt(url)
	begin
		res = Dnsruby::Resolver.new
		ret = res.query(url, Types.TXT)
		ret.answer.map{|answer| 
			if answer.type.to_s.downcase == "txt"
				data = answer.data
			else
				data = answer.to_s
			end
			{ type: answer.type, data: data } 
		}
	rescue
	end
end
def get_nameservers(domain)
	return DnsCheck.new(domain).ns.map(&:name)
end
def get_articles_cname_value
	"custom.intercom.help"
end
def get_root_domain(domain)
	PublicSuffix.domain(domain)
end
def get_dns_hosts(domain)
	hosts = DnsCheck.new(domain).ns.map{|ns|
		get_root_domain(ns.name)
	}
	return hosts.uniq
end

def has_cloudflare_as_dns(dns_hosts)
	return false if dns_hosts.nil? || dns_hosts.empty?
	dns_hosts.each{|dns_host|
		return true if is_cloudflare(dns_host)
	}
	return false
end

def is_cloudflare(dns_host)
	return false if dns_host.nil? || dns_host.empty?
	return dns_host.strip.downcase == "cloudflare.com"
end

def output_log(data)
	return "" if data.nil? || data.strip.empty?
	return "<div class='log'>#{data}</div>"
end

def check_dkim(domain)
	dkim_output = ""
	if !domain.nil? && !domain.strip.empty?
		dkim_output += "<div>Checking domain for DKIM verification: #{domain}....</div>"
		begin
			root_domain = get_root_domain(domain)
		rescue
			dkim_output += "<div class='error'>Problem retrieving root domain. #{abort_message}</div>"
			return dkim_output
		end
		if root_domain != domain
			dkim_output += "<div>Root domain: <code>#{root_domain}</code></div>"
		end

		begin
			dns_hosts = get_dns_hosts(root_domain)
		rescue
			dkim_output += "<div class='error'>Problem retrieving DNS host. Will continue processing but may not be 100% accurate</div>"
		end
		begin
			nameservers = get_nameservers(root_domain) if dns_hosts.nil? || dns_hosts.empty? || dns_hosts.count == 0
		rescue
			dkim_output += "<div class='error'>Problem retrieving nameservers host. . Will continue processing but may not be 100% accurate</div>"
		end
		cname = get_cname(get_intercom_dkim(root_domain))
		double_domain = get_cname(get_intercom_dkim_double_domain(root_domain))
		if dns_hosts
			has_cloudflare_as_dns = has_cloudflare_as_dns(dns_hosts)
			dns_hosts = dns_hosts.first if dns_hosts.count == 1
		end

		if dns_hosts
			dkim_output += "<div>DNS provider: <code>#{dns_hosts}</code></div>"
		end
		if nameservers
			dkim_output += "<div>Nameservers: [#{nameservers.join('][')}]</div>"
		end
		if cname 
			dkim_output += "<div class='success'>CNAME exists for <code>#{get_intercom_dkim(root_domain)}</code>. <BR><code class='indent'>#{cname}</code> <br> Ensure it is the same as what you see in Intercom</div>"
		else
			dkim_output += "<div class='error'>No CNAME exists for <code>#{get_intercom_dkim(root_domain)}</code>. <br> #{dns_check_message}</div>"
		end
		if dns_hosts && has_cloudflare_as_dns
			dkim_output += "<div class='warn'>It looks like you're using Cloudflare. If you're having issues, ensure that you have <a href='https://support.cloudflare.com/hc/en-us/articles/200169056-CNAME-Flattening-RFC-compliant-support-for-CNAME-at-the-root'>disabled CNAME flattening</a> and that the DNS entry has a <a href='https://support.cloudflare.com/hc/en-us/articles/200169626-What-subdomains-are-appropriate-for-orange-gray-clouds-'>gray cloud to ensure the traffic goes to Intercom</a></div>"
		end
		if double_domain
			dkim_output += "<div class='error'>I was able to find a CNAME for <code>#{get_intercom_dkim_double_domain(root_domain)}</code> (note the duplicate <code>#{root_domain}</code>). <BR><code class='indent'>#{double_domain}</code>.</div>"
			dkim_output += "<div class='error'>This is likely an incorrect entry. If you have specified <code>#{get_intercom_dkim(root_domain)}</code> in your DNS server try use <code>#{get_intercom_dkim_base}</code> instead. Some DNS servers automatically add the domain name which can cause this error</div>"
		end


		txts = get_txt(get_intercom_dkim(root_domain))
		if !txts.nil? && txts.count > 0 
			if !txt_has_cname(txts) && txt_has_txt(txts)
				dkim_output += "<div class='error'>TXT record exist for #{get_intercom_dkim(root_domain)}. This will prevent use from verifying the domain</div>"
			elsif txt_has_cname(txts) && txt_has_txt(txts)
			else
				dkim_output += "<div>TXT records exist for #{get_intercom_dkim(root_domain)}. This could prevent verificatin of domian and should be removed <li> #{txts.join('<li>')}</div>"
			end
		end

		dkim_output += "<div class='footnote'>You can also <a href='https://mxtoolbox.com/SuperTool.aspx?action=cname%3a#{get_intercom_dkim(root_domain)}'>check your your domain via MXToolbox</a></div>"
	end
	return dkim_output
end

def dns_check_message
	"Ensure you are modifying the correct DNS server. Check the DNS provider or nameserver details to ensure it matches the server you're modifying"
end
def abort_message
	"Can't complete check. Ensure you have specified a correct domain / URL"
end

def check_custom_domain (custom_domain, use_ssl)
	custom_domain_ssl = (use_ssl && use_ssl.to_s.strip.downcase == "yes")
	custom_domain_output = ""
	if !custom_domain.nil? && !custom_domain.strip.empty?
		custom_domain_output += "<div>Checking Articles Custom Domain: <code>#{custom_domain}</code>....</div>"

		begin
			root_domain = get_root_domain(custom_domain)
		rescue
			custom_domain_output += "<div class='error'>Problem retrieving root domain. #{abort_message}</div>"
			return custom_domain_output
		end

		if root_domain.nil? || root_domain.strip.empty?
			custom_domain_output += "<div class='error'>Problem retrieving root domain. #{abort_message}</div>"
			return custom_domain_output
		end

		begin
			dns_hosts = get_dns_hosts(root_domain)
		rescue
			custom_domain_output += "<div class='error'>Problem retrieving DNS host. Will continue processing but may not be 100% accurate</div>"
		end
		begin
			nameservers = get_nameservers(root_domain) if dns_hosts.nil? || dns_hosts.empty? || dns_hosts.count == 0
		rescue
			custom_domain_output += "<div class='error'>Problem retrieving nameservers. Will continue processing but may not be 100% accurate</div>"
		end

		if dns_hosts
			has_cloudflare_as_dns = has_cloudflare_as_dns(dns_hosts)
			dns_hosts = dns_hosts.first if dns_hosts.count == 1
		end

		if root_domain && root_domain != custom_domain
			custom_domain_output += "<div>Root domain: <code>#{root_domain}</code></div>"
		end
		if dns_hosts
			custom_domain_output += "<div>DNS provider: <code>#{dns_hosts}</code></div>"
		end
		if nameservers
			custom_domain_output += "<div>Nameservers: [#{nameservers.join('][')}]</div>"
		end

		begin
			cname = get_cname(custom_domain)
		rescue
			unless custom_domain_ssl
				custom_domain_output += "<div class='error'>Problem retrieving CNAME on domain. #{abort_message}</div>"
				return custom_domain_output 
			end
		end

		if custom_domain_ssl
			if cname && has_cloudflare_as_dns
				custom_domain_output += "<div class='info'>It looks like you're using Cloudflare but we can detect a CNAME. If you're having issues, ensure that the DNS entry has <a href='https://support.cloudflare.com/hc/en-us/articles/200169626-What-subdomains-are-appropriate-for-orange-gray-clouds-'>an  orange cloud to ensure the traffic goes to Cloudflare to provide the HTTPS</a></div>"
			end

			custom_domain_output += "<div class='info'>For Custom Domains with HTTPS/SSL this will be dependant on your configuration. <ul><li>Ensure you have followed the steps <a href='https://developers.intercom.com/installing-intercom/docs/set-up-your-custom-domain'>in the docs</a></li><li>Or if you have a custom setup get in touch with Intercom, specifying details of your setup</li><li>Check the DNS providers listed to ensure that you are configuring the correct DNS as well</li></ul></div>"

		else
			if cname.nil? || cname.empty?
				className = "error"
				custom_domain_output += "<div class='error'>No CNAME value set up. It needs to be <br><code class='indent'>#{get_articles_cname_value}</code> <br>#{dns_check_message}</div>"
			elsif cname != get_articles_cname_value
				className = "error"
				custom_domain_output += "<div class='error'>Looks like you have an incorrect CNAME value. It needs to be <br><code class='indent'>#{get_articles_cname_value}</code> <br>#{dns_check_message}</div>"
			else
				className = "success"
				custom_domain_output += "<div class='success'>CNAME looks correctly configured</div>"
			end
			custom_domain_output += "<div class='#{className}'>CNAME exists with value <BR><code class='indent'>#{cname}</code></div>" unless (cname.nil? || cname.empty?)
		end

		custom_domain_output += "<div class='footnote'>You can also <a href='https://mxtoolbox.com/SuperTool.aspx?action=cname%3a#{custom_domain}'>check your your domain via MXToolbox</a></div>"
	end
	return custom_domain_output
end

get '/' do
	output = ""
	output += "<html><head>"
	output += "<title>Intercom DNS Check</title>"
	output += "<style type='text/css'>"
	output += "div { padding: 3px } "
	output += "body { font-size: 20px }"
	output += ".info { background-color: #ff6600; color: #ffffff; }"
	output += ".error { background-color: #cc0000; color: #ffffff; }"
	output += ".success { background-color: #009900; color: #ffffff; }"
	output += "div.section { margin-bottom: 1em; padding: 5px; border: 1px solid gray; }"
	output += "div.section h3 { margin: 0;  }"
	output += "div.section code.indent { padding-left: 1em;  }"
	output += "div.section .footnote { margin-top: 1em; font-size: 0.8em; }"
	output += "div.section .log { background-color: #ddd; }"
	output += "form { margin-top: 1em; }"
	output += "form label { font-weight: bold; }"
	output += "form .form-item { margin-bottom: 0.4em; }"
	output += "form .form-item input[type=text] { display: block; width: 20em; font-size: 2em; }\n"
	output += "input[type=submit] { font-size: 16px; border-radius: 5px; background-color: #2D6DC5; color: #ffffff; font-weight: bold; padding: 5px 18px 7px; border: 1px solid rgba(29,54,75,0.2);}"
	output += "input[type=submit]:hover { background-color: #1946C4; }"
	output += "</style></head><body>"
	output += "<h1>Intercom DNS Check</h1>"
	output += "<h3>Check your Intercom DKIM / Article Custom domain DNS settings</h3>"

	dkim_output = check_dkim(params["dkim_domain"])

	custom_domain_output = check_custom_domain(params["custom_domain"], params["custom_domain_ssl"])
	
	output += "<div class='section'>"
	output += "<h3>DKIM Domain verification for sending Messages</h3>"
	output += "<a href='https://www.intercom.com/help/configure-intercom-for-your-product-or-site/configure-intercom-for-your-team/a-guide-to-sending-email-from-your-own-address'>Intercom Docs</a>"
	output += "<form method='get' action='/'>"
	output += "<div class='form-item'><label>Domain to check: <input type='text' name='dkim_domain' value='#{params["dkim_domain"]}'></label></div>"
	output += "<input type='submit' value='Check domain!'> (Enter in the format of <code>subdomain.domain.com</code>: remove any http / https prefix)"
	output += "</form>"
	output += output_log(dkim_output)
	output += "</div>"
	output += "<div class='section'>"	
	output += "<h3>Custom Domain for Articles</h3>"
	output += "<a href='https://developers.intercom.com/installing-intercom/docs/set-up-your-custom-domain'>Intercom Docs</a>"
	output += "<form method='get' action='/'>"
	output += "<div class='form-item'>Setting up HTTPS/SSL?"
	output += "<label><input type='radio' name='custom_domain_ssl' value='no' #{(params["custom_domain_ssl"] == "yes" ? "" : "checked")}>No</label>"
	output += "<label><input type='radio' name='custom_domain_ssl' value='yes' #{(params["custom_domain_ssl"] == "yes" ? "checked" : "")}>Yes</label></div>"
	output += "<div class='form-item'><label>Domain to check: <input type='text' name='custom_domain' value='#{params["custom_domain"]}'></label></div>"
	output += "<input type='submit' value='Check Domain!'>"
	output += " (Enter in the format of <code>subdomain.domain.com</code>: remove any http / https prefix)"
	output += "</form>"
	output += output_log(custom_domain_output)
	output += "</div>"
	output += "<hr>"
	output += "<a href='https://github.com/thewheat/intercom-dns-check'>Source</a>"
	output += "</body></html>"
	output
end

