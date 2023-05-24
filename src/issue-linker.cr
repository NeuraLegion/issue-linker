require "option_parser"
require "http"
require "tallboy"
require "colorize"
require "sec_tester"

require "./vendors//snyk/snyk.cr"
require "./bright_issue.cr"

module Issue::Linker
  VERSION = "0.4.0"
end

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

case vendor
when "Snyk"
  case subcommand
  when "LinkIssues"
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
    when options["bright_token"]?.nil?
      STDERR.puts "ERROR: --bright-token is required"
      STDERR.puts parser
      exit(1)
    when options["bright_scan"]?.nil?
      STDERR.puts "ERROR: --bright-scan is required"
      STDERR.puts parser
      exit(1)
    end

    snyk = Issue::Linker::Snyk.new(
      snyk_token: options["snyk_token"],
      snyk_org: options["snyk_org"],
      snyk_project: options["snyk_project"],
      bright_token: options["bright_token"],
      bright_scan: options["bright_scan"],
      output: options["output"]? || "json",
      update: options["update"]? ? true : false,
    )

    snyk.link
    snyk.draw
  when "VerificationScan"
    snyk = Issue::Linker::Snyk.new(
      snyk_token: options["snyk_token"],
      snyk_org: options["snyk_org"],
      snyk_project: options["snyk_project"],
      bright_token: options["bright_token"],
      output: options["output"]? || "json",
    )
    snyk.verification_scan(options["target"])
  else
    STDERR.puts "ERROR: #{subcommand} is not a valid subcommand."
    STDERR.puts "You can use `issues-linker Snyk --help` to see available subcommands."
    STDERR.puts parser
    exit(1)
  end
end
