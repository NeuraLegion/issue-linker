require "option_parser"
require "http"
require "tallboy"
require "colorize"
require "sec_tester/target"
require "sec_tester/tests"

require "./vendors//snyk/snyk.cr"
require "./vendors/cx/cx.cr"
require "./vendors/shiftleft/shiftleft.cr"
require "./vendors/bright/bright.cr"
require "./linker.cr"

module Issue::Linker
  VERSION = "0.6.0"
end

alias VendorIssue = Issue::Linker::CXIssue | Issue::Linker::SnykIssue | Issue::Linker::ShiftLeftIssue
alias Vendor = Issue::Linker::CX | Issue::Linker::Snyk | Issue::Linker::ShiftLeft

options = Hash(String, String).new
vendor = nil
subcommand = nil

parser = OptionParser.parse do |parser|
  parser.banner = "Usage: issue-linker [subcommand] [arguments]"
  parser.on("Snyk", "Snyk Integration") do
    vendor = "Snyk"
    parser.on("Link-Issues", "Link Snyk and Bright issues") do
      subcommand = "LinkIssues"
      parser.on("--snyk-token TOKEN", "Api-Key for the snyk platform") { |token| options["snyk_token"] = token }
      parser.on("--snyk-org ORG", "Snyk org UUID") { |org| options["snyk_org"] = org }
      parser.on("--snyk-project PROJECT", "Snyk project UUID") { |project| options["snyk_project"] = project }
      parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
      parser.on("--bright-scan SCAN", "Bright scan ID") { |scan| options["bright_scan"] = scan }
      parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
      parser.on("--update", "Update Bright issues with Snyk issue links") { |update| options["update"] = "true" }
    end
    parser.on("Verification-Scan", "Run a verification scan based on Snyk Code findings") do
      subcommand = "VerificationScan"
      parser.on("--snyk-token TOKEN", "Api-Key for the snyk platform") { |token| options["snyk_token"] = token }
      parser.on("--snyk-org ORG", "Snyk org UUID") { |org| options["snyk_org"] = org }
      parser.on("--snyk-project PROJECT", "Snyk project UUID") { |project| options["snyk_project"] = project }
      parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
      parser.on("-t TARGET", "--target TARGET", "Target to scan by bright DAST") { |target| options["target"] = target }
      parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
    end
  end
  parser.on("CX", "Checkmarx") do
    vendor = "CX"
    parser.on("Link-Issues", "Link CX and Bright issues") do
      subcommand = "LinkIssues"
      parser.on("--cx-token TOKEN", "Api-Key for the Checkmarx platform") { |token| options["cx_token"] = token }
      parser.on("--cx-scan SCAN", "Checkmarx scan UUID") { |scan| options["cx_scan"] = scan }
      parser.on("--cx-mfa", "Use MFA token that needs refreshing") { |mfa| options["mfa"] = "true" }
      parser.on("--cx-realm REALM", "Checkmarx realm") { |realm| options["realm"] = realm }
      parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
      parser.on("--bright-scan SCAN", "Bright scan ID") { |scan| options["bright_scan"] = scan }
      parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
      parser.on("--update", "Update Bright issues with Checkmarx issue links") { |update| options["update"] = "true" }
    end
    parser.on("Verification-Scan", "Run a verification scan based on Checkmarx findings") do
      subcommand = "VerificationScan"
      parser.on("--cx-token TOKEN", "Api-Key for the Checkmarx platform") { |token| options["cx_token"] = token }
      parser.on("--cx-scan SCAN", "Checkmarx scan UUID") { |scan| options["scan"] = scan }
      parser.on("--cx-mfa", "Use MFA token that needs refreshing") { |mfa| options["mfa"] = "true" }
      parser.on("--cx-realm REALM", "Checkmarx realm") { |realm| options["realm"] = realm }
      parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
      parser.on("-t TARGET", "--target TARGET", "Target to scan by bright DAST") { |target| options["target"] = target }
      parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
    end
  end
  parser.on("ShiftLeft", "Qwiet") do
    vendor = "ShiftLeft"
    parser.on("Link-Issues", "Link ShiftLeft and Bright issues") do
      subcommand = "LinkIssues"
      parser.on("--shiftleft-token TOKEN", "Api-Key for the ShiftLeft platform") { |token| options["shiftleft_token"] = token }
      parser.on("--shiftleft-app APP", "ShiftLeft Application name (ID)") { |app| options["shiftleft_app"] = app }
      parser.on("--shiftleft-org ORG", "ShiftLeft ORG ID (UUID)") { |org| options["shiftleft_org"] = org }
      parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
      parser.on("--bright-scan SCAN", "Bright scan ID") { |scan| options["bright_scan"] = scan }
      parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
      parser.on("--update", "Update Bright issues with ShiftLeft issue links") { |update| options["update"] = "true" }
    end
    parser.on("Verification-Scan", "Run a verification scan based on ShiftLeft findings") do
      subcommand = "VerificationScan"
      parser.on("--shiftleft-token TOKEN", "Api-Key for the ShiftLeft platform") { |token| options["shiftleft_token"] = token }
      parser.on("--shiftleft-app APP", "ShiftLeft Application name (ID)") { |app| options["shiftleft_app"] = app }
      parser.on("--shiftleft-org ORG", "ShiftLeft ORG ID (UUID)") { |org| options["shiftleft_org"] = org }
      parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
      parser.on("-t TARGET", "--target TARGET", "Target to scan by bright DAST") { |target| options["target"] = target }
      parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
    end
  end
  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit
  end
  parser.invalid_option do |flag|
    STDERR.puts "ERROR: #{flag} is not a valid option."
    STDERR.puts parser
    exit(1)
  end
  if ARGV.empty?
    STDERR.puts parser
    exit(1)
  end
end

# Bright options validation
if options["bright_token"]?.nil?
  STDERR.puts "ERROR: --bright-token is required"
  STDERR.puts parser
  exit(1)
end
if options["bright_scan"]?.nil?
  STDERR.puts "ERROR: --bright-scan is required"
  STDERR.puts parser
  exit(1)
end

bright = Issue::Linker::Bright.new(
  bright_token: options["bright_token"],
  bright_scan: options["bright_scan"]
)

case vendor
when "Snyk"
  # Validate options and ensure required options are provided
  case options
  when options["snyk_token"]?.nil?
    STDERR.puts "ERROR: --snyk-token is required"
    STDERR.puts parser
    exit(1)
  when options["snyk_org"]?.nil?
    STDERR.puts "ERROR: --snyk-org is required"
    STDERR.puts parser
    exit(1)
  when options["snyk_project"]?.nil?
    STDERR.puts "ERROR: --snyk-project is required"
    STDERR.puts parser
    exit(1)
  end
  case subcommand
  when "LinkIssues"
    snyk = Issue::Linker::Snyk.new(
      snyk_token: options["snyk_token"],
      snyk_org: options["snyk_org"],
      snyk_project: options["snyk_project"]
    )

    linker = Issue::Linker::Link.new(
      vendor: snyk,
      bright: bright,
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )
    linker.link
    linker.draw
  when "VerificationScan"
    snyk = Issue::Linker::Snyk.new(
      snyk_token: options["snyk_token"],
      snyk_org: options["snyk_org"],
      snyk_project: options["snyk_project"]
    )

    linker = Issue::Linker::Link.new(
      vendor: snyk,
      bright: bright,
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )
    linker.verification_scan(options["target"])
  else
    STDERR.puts "ERROR: #{subcommand} is not a valid subcommand."
    STDERR.puts "You can use `issues-linker Snyk --help` to see available subcommands."
    STDERR.puts parser
    exit(1)
  end
when "CX"
  case options
  when options["cx_token"]?.nil?
    STDERR.puts "ERROR: --cx-token is required"
    STDERR.puts parser
    exit(1)
  when options["cx_scan"]?.nil?
    STDERR.puts "ERROR: --cx-scan is required"
    STDERR.puts parser
    exit(1)
  end

  if options["mfa"]?
    if options["realm"]?.nil?
      STDERR.puts "ERROR: --cx-realm is required when using MFA"
      STDERR.puts parser
      exit(1)
    end
  end
  case subcommand
  when "LinkIssues"
    # Validate options and ensure required options are provided

    cx = Issue::Linker::CX.new(
      token: options["cx_token"],
      cx_scan: options["cx_scan"],
      mfa: options["mfa"]? ? true : false,
      realm: options["realm"]?,
    )

    linker = Issue::Linker::Link.new(
      vendor: cx,
      bright: bright,
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )
    linker.link
    linker.draw
  when "VerificationScan"
    cx = Issue::Linker::CX.new(
      token: options["cx_token"],
      cx_scan: options["cx_scan"],
      mfa: options["mfa"]? ? true : false,
      realm: options["realm"]?,
    )
    linker = Issue::Linker::Link.new(
      vendor: cx,
      bright: bright,
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )
    linker.verification_scan(options["target"])
  else
    STDERR.puts "ERROR: #{subcommand} is not a valid subcommand."
    STDERR.puts "You can use `issues-linker Checkmarx --help` to see available subcommands."
    STDERR.puts parser
    exit(1)
  end
when "ShiftLeft"
  # Validate options and ensure required options are provided
  case options
  when options["shiftleft_token"]?.nil?
    STDERR.puts "ERROR: --shiftleft-token is required"
    STDERR.puts parser
    exit(1)
  when options["shiftleft_app"]?.nil?
    STDERR.puts "ERROR: --shiftleft-app is required"
    STDERR.puts parser
    exit(1)
  when options["shiftleft_org"]?.nil?
    STDERR.puts "ERROR: --shiftleft-org is required"
    STDERR.puts parser
    exit(1)
  end

  case subcommand
  when "LinkIssues"
    shiftleft = Issue::Linker::ShiftLeft.new(
      api_key: options["shiftleft_token"],
      app_id: options["shiftleft_app"],
      org_id: options["shiftleft_org"]
    )

    linker = Issue::Linker::Link.new(
      vendor: shiftleft,
      bright: bright,
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )
    linker.link
    linker.draw
  when "VerificationScan"
    shiftleft = Issue::Linker::ShiftLeft.new(
      api_key: options["shiftleft_token"],
      app_id: options["shiftleft_app"],
      org_id: options["shiftleft_org"]
    )

    linker = Issue::Linker::Link.new(
      vendor: shiftleft,
      bright: bright,
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )
    linker.verification_scan(options["target"])
  else
    STDERR.puts "ERROR: #{subcommand} is not a valid subcommand."
    STDERR.puts "You can use `issues-linker ShiftLeft --help` to see available subcommands."
    STDERR.puts parser
    exit(1)
  end
end
