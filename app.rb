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

def test
	url = 'intercom._domainkey.thewheatfield.org'
	url = 'intercom._domainkey.thewheatfield.org.thewheatfield.org'
	begin
		      resolver = Dnsruby::Resolver.new(packet_timeout: 5, retry_delay: 5, retry_times: 3,
                                       nameserver: NAMESERVERS)

	  r = Resolv::DNS.open do |dns|
	    dns.getresource(url, Resolv::DNS::Resource::IN::TXT)
#	    dns.getresource(url, Resolv::DNS::Resource::IN::CNAME)
	  end
	  puts r.inspect
	  #puts r.name.to_s # => return alias domain
	rescue Resolv::ResolvError => e
	  # handle error
	end
end

def getHost(url)
	myUri = URI.parse("http://#{url}")
	myUri.host
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
def get_dns_host(domain)
	hosts = DnsCheck.new(domain).ns.map{|ns|
		get_root_domain(ns.name)
	}
	return hosts.uniq
end

def is_cloudflare(dns_host)
	return false if dns_host.nil? || dns_host.empty?
	return dns_host.strip.downcase == "cloudflare.com"
end

def output_log(data)
	return "" if data.nil? || data.strip.empty?
	return "<div class='log'>#{data}</div>"
end

get '/' do
	output = ""
	output += "<html><head><style type='text/css'>"
	output += "div { padding: 3px } "
	output += "body { font-size: 20px }"
	output += ".info { background-color: #ff6600; color: #ffffff; }"
	output += ".error { background-color: #cc0000; color: #ffffff; }"
	output += ".success { background-color: #009900; color: #ffffff; }"
	output += "div.section { margin-bottom: 1em; padding: 5px; border: 1px solid gray; }"
	output += "div.section h3 { margin: 0;  }"
	output += "div.section code.indent { padding-left: 1em;  }"
	output += "div.section .footnote { margin-top: 1em; font-size: 0.8em; }"
	output += "div.section .log { background-color: #ccc; }"

	output += "</style></head><body>"

	dkim_output = ""
	domain = params["dkim_domain"]
	if !domain.nil? && !domain.strip.empty?
		dkim_output += "<div class=''>Checking domain for DKIM verification: #{domain}....</div>"
		root_domain = get_root_domain(domain)
		if root_domain != domain
			dkim_output += "<div class=''>Root domain: <code>#{root_domain}</code></div>"
		end
		dns_host = get_dns_host(root_domain)
		nameservers = get_nameservers(root_domain) if dns_host.nil? || dns_host.empty? || dns_host.count == 0
		cname = get_cname(get_intercom_dkim(root_domain))
		double_domain = get_cname(get_intercom_dkim_double_domain(root_domain))
		dns_host = dns_host.first if dns_host.count == 1 

		if dns_host
			dkim_output += "<div class=''>DNS provider: <code>#{dns_host}</code></div>"
		end
		if nameservers
			dkim_output += "<div class=''>Nameservers: [#{nameservers.join('][')}]</div>"
		end
		if cname 
			dkim_output += "<div class='success'>CNAME exists for #{get_intercom_dkim(root_domain)}. <BR><code class='indent'>#{cname}</code> <br> Ensure it is the same as what you see in Intercom</div>"
		end
		if dns_host && is_cloudflare(dns_host)
			dkim_output += "<div class='warn'>It looks like you're using Cloudflare. If you're having issues, ensure that you have <a href='https://support.cloudflare.com/hc/en-us/articles/200169056-CNAME-Flattening-RFC-compliant-support-for-CNAME-at-the-root'>disabled CNAME flattening</a> and that the DNS entry has a <a href='https://support.cloudflare.com/hc/en-us/articles/200169626-What-subdomains-are-appropriate-for-orange-gray-clouds-'>gray cloud to ensure the traffic goes to Intercom</a></div>"
		end
		if double_domain
			dkim_output += "<div class='error'>CNAME exist for #{get_intercom_dkim_double_domain(root_domain)}. <BR><code class='indent'>#{double_domain}</code>.</div>"
			dkim_output += "<div class='error'>This is likely an incorrect entry. If you have specified <code>#{get_intercom_dkim(root_domain)}</code> in your DNS server try use <code>#{get_intercom_dkim_base}</code> instead. Some DNS servers automatically add the domain name which can cause this error</div>"
		end


		txts = get_txt(get_intercom_dkim(root_domain))
		if !txts.nil? && txts.count > 0 
			if !txt_has_cname(txts) && txt_has_txt(txts)
				dkim_output += "<div class='error'>TXT record exist for #{get_intercom_dkim(root_domain)}. This will prevent use from verifying the domain</div>"
			elsif txt_has_cname(txts) && txt_has_txt(txts)
			else
				dkim_output += "<div class=''>TXT records exist for #{get_intercom_dkim(root_domain)}. This could prevent verificatin of domian and should be removed <li> #{txts.join('<li>')}</div>"
			end
		end

		dkim_output += "<div class='footnote'>You can also <a href='https://mxtoolbox.com/SuperTool.aspx?action=cname%3a#{get_intercom_dkim(root_domain)}'>check your your domain via MXToolbox</a></div>"
	end

	custom_domain = params["custom_domain"]
	custom_domain_output = ""
	if !custom_domain.nil? && !custom_domain.strip.empty?
		custom_domain_output += "<div class=''>Checking Articles Custom Domain: <code>#{custom_domain}</code>....</div>"
		root_domain = get_root_domain(custom_domain)
		dns_host = get_dns_host(root_domain)
		nameservers = get_nameservers(root_domain) if dns_host.nil? || dns_host.empty? || dns_host.count == 0
		cname = get_cname(custom_domain)
		if cname.nil? || cname.empty?
			className = "error"
			custom_domain_output += "<div class='error'>No CNAME value set up. It needs to be <br><code class='indent'>#{get_articles_cname_value}</code></div>"
		elsif cname != get_articles_cname_value
			className = "error"
			custom_domain_output += "<div class='error'>Looks like you have an incorrect CNAME value. It needs to be <br><code class='indent'>#{get_articles_cname_value}</code></div>"
		else
			className = "success"
			custom_domain_output += "<div class='success'>CNAME looks correctly configured</div>"
		end
		custom_domain_output += "<div class='#{className}'>CNAME exists with value <BR><code class='indent'>#{cname}</code></div>" unless (cname.nil? || cname.empty?)

		custom_domain_output += "<HR>"

		dns_host = dns_host.first if dns_host.count == 1
		if root_domain != custom_domain
			custom_domain_output += "<div class=''>Root domain: <code>#{root_domain}</code></div>"
		end
		if dns_host
			custom_domain_output += "<div class=''>DNS provider: <code>#{dns_host}</code></div>"
		end
		if nameservers
			custom_domain_output += "<div class=''>Nameservers: [#{nameservers.join('][')}]</div>"
		end
		custom_domain_output += "<div class='footnote'>You can also <a href='https://mxtoolbox.com/SuperTool.aspx?action=cname%3a#{domain}'>check your your domain via MXToolbox</a></div>"
	end
	
	output += "<div class='section'>"
	output += "<h3>DKIM Domain verification for sending Messages</h3>"
	output += "<a href='https://www.intercom.com/help/configure-intercom-for-your-product-or-site/configure-intercom-for-your-team/a-guide-to-sending-email-from-your-own-address'>Intercom Docs</a>"
	output += "<form method='get' action='/'>"
	output += "<label>Domain to check: <input type='text' name='dkim_domain'></label>"
	output += "<input type='submit' value='Check domain!'>"
	output += "</form>"
	output += output_log(dkim_output)
	output += "</div>"
	output += "<div class='section'>"	
	output += "<h3>Custom Domain for Articles</h3>"
	output += "<a href='https://developers.intercom.com/installing-intercom/docs/set-up-your-custom-domain'>Intercom Docs</a>"
	output += "<form method='get' action='/'>"
	output += "<label>Domain to check: <input type='text' name='custom_domain'></label>"
	output += "<input type='submit' value='Check Domain!'>"
	output += "</form>"
	output += output_log(custom_domain_output)
	output += "</div>"
	output += "</body></html>"
	output
end
