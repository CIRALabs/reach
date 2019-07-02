class DPPCode
  attr_accessor :key, :keybinary, :mac, :smarkaklink, :llv6, :essid
  attr_accessor :dpphash
  attr_accessor :dppcode
  attr_accessor :linkname

  class DPPKeyError < Exception; end

  def initialize(str = nil)
    if ENV['INTERFACE']
      self.linkname = ENV['INTERFACE']
    else
      self.linkname = "wlan0"
    end

    if str
      self.dppcode = str
      parse_dpp
    end
  end

  def dpphash
    @dpphash ||= Hash.new
  end

  def parse_one_item(item)
    letter,rest = item.split(/:/, 2)

    dpphash[letter] = rest
    case letter
    when 'S'
      self.smarkaklink = rest
    when 'M'
      self.mac = rest
    when 'K'
      begin
        self.keybinary = Base64.strict_decode64(rest)
        self.key = OpenSSL::PKey.read(keybinary)
      rescue OpenSSL::PKey::PKeyError
        raise DPPKeyError
      rescue ArgumentError  # invalid base 64
        raise DPPKeyError
      end
    when 'L'
      self.llv6= rest
    when 'E'
      self.essid= rest
    end
  end

  def ecdsa_key
    @ecdsa ||= ECDSA::Format::PubKey.decode(key)
  end

  def parse_dpp
    return if dppcode.blank?

    return unless dppcode[0..3].upcase == 'DPP:'
    dppcodes = dppcode[4..-1]

    colons = dppcodes.split(/;/)

    item = colons.shift
    while item
      parse_one_item(item)
      item = colons.shift
    end
  end

  # turn compressed hex IPv6 address into something useable for HTTPS
  # use IPAddress module
  def llv6_host
    iid=ACPAddress::parse_hex llv6
    ll = iid.set_ll_prefix
    ll.to_s + "%" + linkname
  end

  def llv6_as_iauthority
    "[" + llv6_host + "]"
  end

  # this routine looks for ULA addresses, and then it picks out the
  # appropriate name, and turns into an appropriate name.
  # this should REALLY work by sending an mDNS unicast query to
  # the LL-v6 address asking for resolution of the name "mud"
  #
  # for testing purposes, this is right now hard coded to [::2]
  def ulanodename_iauthority
    ENV['NODENAME'] || "n3CE618.router.securehomegateway.ca"
  end

  def mudport
    ENV['NODEPORT'] || 8081
  end

  # this returns a NET::HTTP that is connected to the correct end point,
  # having provided the correct Host: header (and SNI!), but occurs over
  # an IPv6 LL connection.
  # note that while VERIFY_NONE is specified, the certificate chain is verified
  # after connection.
  def llnode_request
    options = {
      :verify_mode => OpenSSL::SSL::VERIFY_NONE,
      :use_ssl => true,
      :cert    => PledgeKeys.instance.ldevid_pubkey,
      :key     => PledgeKeys.instance.ldevid_privkey
    }
    @ll_pledge_handler = Net::HTTP.new(llv6_host, mudport)
    #@ll_pledge_handler.set_debug_output($stderr)

    @ll_pledge_handler.use_ssl = true
    @ll_pledge_handler.cert = PledgeKeys.instance.ldevid_pubkey
    @ll_pledge_handler.key  = PledgeKeys.instance.ldevid_privkey
    #@ll_pledge_handler.server_name = ulanodename_iauthority.downcase

    # turn off internal verification, do it ourselves.
    @ll_pledge_handler.verify_mode = OpenSSL::SSL::VERIFY_NONE

    # bring up the connection
    @ll_pledge_handler.start

    name = ulanodename_iauthority.downcase
    peer_cert = OpenSSL::X509::Certificate.new(@ll_pledge_handler.peer_cert)

    unless OpenSSL::SSL.verify_certificate_identity(peer_cert, name)

      puts "Certificate does not validate the connection to #{name}, says: #{peer_cert.subject.to_s}"
      return nil
    end
    @ll_pledge_handler
  end

  # decode the iauthority or URL found in the S field, and turn it into a full
  # URL
  def self.canonicalize_masa_url(url)
    if !url.blank? and !url.include?("/")
      url = "https://" + url + "/.well-known/est/"
    else
      # make sure that there is a trailing /
      unless url[-1] == "/"
        url ||= "/"
      end
    end
    url
  end

  def smarkaklink_enroll_url
    URI.join(self.class.canonicalize_masa_url(smarkaklink), "smarkaklink")
  end

end
