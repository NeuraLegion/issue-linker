require "option_parser"
require "http"
require "tallboy"
require "colorize"

require "./snyk_issue.cr"
require "./bright_issue.cr"

module Issue::Linker
  VERSION = "0.2.0"

  class Run
    @snyk_token : String
    @snyk_org : String
    @snyk_project : String
    @bright_token : String
    @bright_scan : String
    @bright_cluster : String = ENV["BRIGHT_CLUSTER"]? || "app.brightsec.com"
    @output : String
    @update : Bool
    @all_links : Hash(SnykIssue, BrightIssue) = Hash(SnykIssue, BrightIssue).new

    def initialize(@snyk_token, @snyk_org, @snyk_project, @bright_token, @bright_scan, @output, @update)
    end

    # Link Snyk issues to Bright issues
    # This is done by comparing cwe and issue names
    def link
      snyk_issues = get_snyk_issues
      bright_issues = get_bright_issues
      already_linked_ids = Array(String).new

      snyk_issues.each do |snyk_issue|
        bright_issues.each do |bright_issue|
          if snyk_issue.attributes.cwe.any? { |cwe| cwe.downcase == bright_issue.cwe.downcase } || (snyk_issue.attributes.title.includes?(bright_issue.name) || bright_issue.name.includes?(snyk_issue.attributes.title))
            next if already_linked_ids.includes?(bright_issue.id) || already_linked_ids.includes?(snyk_issue.id)
            @all_links[snyk_issue] = bright_issue
            already_linked_ids << bright_issue.id
            already_linked_ids << snyk_issue.id
          end
        end
      end

      if @update
        update
      end
    end

    def draw
      case @output
      when "json"
        output_json
      when "markdown", "ascii"
        draw_table
      end
    end

    def update
      headers = HTTP::Headers{
        "Authorization" => "Api-Key #{@bright_token}",
        "Content-Type"  => "application/json",
        "Accept"        => "application/json",
      }
      comments_url = "https://#{@bright_cluster}/api/v1/comments"

      @all_links.each do |link|
        resp = HTTP::Client.post(
          comments_url,
          headers: headers,
          body: {
            includedInReport: true,
            scanId:           @bright_scan,
            issueId:          link[1].id,
            body:             <<-EOF
              ![snyk-logo](https://res.cloudinary.com/snyk/image/upload/w_100,h_100/v1537345891/press-kit/brand/avatar-transparent.png)

              • This issue is linked to [Snyk issue ##{link[0].id}](#{snyk_issue_url(link[0])})
              EOF
          }.to_json,
        )

        unless resp.status.success?
          STDERR.puts "ERROR: Failed to update Bright issue #{link[1].id}"
          STDERR.puts resp.body.to_s
          exit(1)
        end
      end
    end

    private def output_json
      links = Array(Hash(String, Hash(String, Array(String) | String) | Hash(String, String))).new
      @all_links.each do |k, v|
        links << {
          "snyk_issue" => {
            "id"    => k.id,
            "title" => k.attributes.title,
            "cwe"   => k.attributes.cwe,
            "url"   => snyk_issue_url(k),
          },
          "bright_issue" => {
            "id"   => v.id,
            "name" => v.name,
            "cwe"  => v.cwe,
            "url"  => bright_issue_url(v),
          },
        }
      end
      print links.to_json
    end

    # draw a table of links
    # the table should have the following columns:
    #   - Issue name
    #   - CWE
    #   - Snyk issue URL
    #   - Bright issue URL
    private def draw_table
      table = Tallboy.table do
        header [
          "Issue name",
          "CWE",
          "Snyk issue URL",
          "Bright issue URL",
        ]

        @all_links.each do |link|
          row [
            link[0].attributes.title,
            link[0].attributes.cwe.first,
            "[Snyk Issue URL](#{snyk_issue_url(link[0])})",
            "[Bright Issue URL](#{bright_issue_url(link[1])})",
          ]
        end
      end
      case @output
      when "markdown"
        puts table.render(:markdown)
      when "ascii"
        puts table
      end
    end

    private def snyk_issue_url(issue : SnykIssue) : String
      org_name = snyk_org_name(@snyk_org)
      "https://app.snyk.io/org/#{org_name}/project/#{@snyk_project}#issue-#{issue.id}"
    end

    private def bright_issue_url(issue : BrightIssue) : String
      "https://#{@bright_cluster}/scans/#{@bright_scan}/issues/#{issue.id}"
    end

    # translate snyk org id to org name
    private def snyk_org_name(id : String) : String
      headers = HTTP::Headers{
        "Accept"        => "application/vnd.api+json",
        "authorization" => "#{@snyk_token}",
      }
      resp = HTTP::Client.get(
        "https://api.snyk.io/rest/orgs?version=2023-03-21~experimental",
        headers: headers
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to get Snyk orgs"
        STDERR.puts resp.body.to_s
        exit(1)
      end

      JSON.parse(resp.body.to_s)["data"].as_a.each do |org|
        if org["id"] == id
          return org["attributes"]["name"].as_s
        end
      end

      raise "Failed to find Snyk org name based on given org id"
    end

    # Get Snyk issues
    private def get_snyk_issues : Array(SnykIssue)
      snyk_url = "https://api.snyk.io/rest/orgs/#{@snyk_org}/code_issue_summaries?project_id=#{@snyk_project}&version=2023-03-21~experimental&limit=100"
      headers = HTTP::Headers{
        "Accept"        => "application/vnd.api+json",
        "authorization" => "#{@snyk_token}",
      }
      resp = HTTP::Client.get(
        snyk_url,
        headers: headers
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to get Snyk issues"
        STDERR.puts resp.body.to_s
        exit(1)
      end

      resp_json = JSON.parse(resp.body.to_s)
      Array(SnykIssue).from_json(resp_json["data"].to_json)
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Snyk response"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end

    # Get Bright issues
    private def get_bright_issues : Array(BrightIssue)
      headers = HTTP::Headers{
        "Authorization" => "Api-Key #{@bright_token}",
        "Content-Type"  => "application/json",
        "Accept"        => "application/json",
      }

      bright_url = "https://#{@bright_cluster}/api/v1/scans/#{@bright_scan}/issues"

      resp = HTTP::Client.get(
        bright_url,
        headers: headers
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to get Bright issues"
        STDERR.puts resp.body.to_s
        exit(1)
      end

      Array(BrightIssue).from_json(resp.body.to_s)
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Bright response"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end
  end
end

options = Hash(String, String).new

parser = OptionParser.parse do |parser|
  parser.banner = "Usage: issue-linker [arguments]"
  parser.on("--snyk-token TOKEN", "Api-Key for the snyk platform") { |token| options["snyk_token"] = token }
  parser.on("--snyk-org ORG", "Snyk org UUID") { |org| options["snyk_org"] = org }
  parser.on("--snyk-project PROJECT", "Snyk project UUID") { |project| options["snyk_project"] = project }
  parser.on("--bright-token TOKEN", "Api-Key for the Bright platform") { |token| options["bright_token"] = token }
  parser.on("--bright-scan SCAN", "Bright scan ID") { |scan| options["bright_scan"] = scan }
  parser.on("--output TYPE", "Type of Output, default: json. [json,markdown,ascii] (Optional)") { |output| options["output"] = output }
  parser.on("--update", "Update Bright issues with Snyk issue links") { |update| options["update"] = "true" }
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

runner = Issue::Linker::Run.new(
  snyk_token: options["snyk_token"],
  snyk_org: options["snyk_org"],
  snyk_project: options["snyk_project"],
  bright_token: options["bright_token"],
  bright_scan: options["bright_scan"],
  output: options["output"]? || "json",
  update: options["update"]? ? true : false,
)

runner.link
runner.draw
