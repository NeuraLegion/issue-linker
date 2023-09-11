require "./bright_issue.cr"

module Issue::Linker
  class Bright
    @bright_token : String
    @bright_scan : String?
    @bright_cluster : String = ENV["BRIGHT_CLUSTER"]? || "app.brightsec.com"

    def initialize(@bright_token, @bright_scan = nil)
    end

    # Run a verification scan based on the Snyk project findings
    # This will start a scan on Bright, the tests to run will be based on the Snyk findings
    def verification_scan(target : String, issues : Array(String)) : String
      # validate target
      verified_target = SecTester::Target.new(target)

      # create a new scan, return scan id
      start_bright_scan(target_url: verified_target.url, tests: issues)
    end

    def update(bright_issue : BrightIssue, source_path : String, issue_url : String, vendor_logo : String = "")
      headers = HTTP::Headers{
        "Authorization" => "Api-Key #{@bright_token}",
        "Content-Type"  => "application/json",
        "Accept"        => "application/json",
      }
      comments_url = "https://#{@bright_cluster}/api/v1/comments"

      resp = HTTP::Client.post(
        comments_url,
        headers: headers,
        body: {
          includedInReport: true,
          scanId:           @bright_scan,
          issueId:          bright_issue.id,
          body:             <<-EOF
          ## SAST Issue Correlation
          • Source Code File: #{source_path}
          <br>
          • This issue is linked to #{issue_url}
          <br>
          #{vendor_logo}
          EOF
        }.to_json,
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to update Bright issue #{bright_issue.id}"
        STDERR.puts resp.body.to_s
        exit(1)
      end
    end

    # Start a new scan on Bright
    def start_bright_scan(tests : Array(String), target_url : String)
      headers = HTTP::Headers{
        "Authorization" => "Api-Key #{@bright_token}",
        "Content-Type"  => "application/json",
        "Accept"        => "application/json",
      }

      bright_url = "https://#{@bright_cluster}/api/v1/scans"

      body = {
        "name":                 "Vendor verification scan #{Time.utc}",
        "module":               "dast",
        "tests":                tests,
        "fileId":               nil,
        "attackParamLocations": ["query", "body", "fragment"],
        "discoveryTypes":       ["crawler"],
        "crawlerUrls":          [target_url],
        "smart":                true,
        "skipStaticParams":     true,
        "projectId":            get_bright_first_project_id,
        "slowEpTimeout":        nil,
        "targetTimeout":        nil,
        "authObjectId":         nil,
        "templateId":           nil,
        "info":                 {
          "source": "utlib",
          "client": {
            "name":    "issue_linker",
            "version": Issue::Linker::VERSION,
          },
          "provider": "unkown",
        },
      }.to_json

      resp = HTTP::Client.post(
        bright_url,
        headers: headers,
        body: body
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to start Bright scan"
        STDERR.puts resp.body.to_s
        exit(1)
      end

      JSON.parse(resp.body.to_s)["id"].to_s
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Bright response"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end

    private def get_bright_first_project_id : String
      headers = HTTP::Headers{
        "Authorization" => "Api-Key #{@bright_token}",
        "Content-Type"  => "application/json",
        "Accept"        => "application/json",
      }

      bright_url = "https://#{@bright_cluster}/api/v1/projects"

      resp = HTTP::Client.get(
        bright_url,
        headers: headers,
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to get Bright project id"
        STDERR.puts resp.body.to_s
        exit(1)
      end

      JSON.parse(resp.body.to_s).as_a.first["id"].to_s
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Bright response"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end

    def issue_url(issue : BrightIssue) : String
      "https://#{@bright_cluster}/scans/#{@bright_scan}/issues/#{issue.id}"
    end

    # Get Bright issues
    def get_bright_issues : Array(BrightIssue)
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
