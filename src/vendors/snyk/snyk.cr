require "./snyk_issue.cr"

module Issue::Linker
  class Snyk
    @snyk_token : String
    @snyk_org : String
    @snyk_project : String
    @bright_token : String
    @bright_scan : String?
    @bright_cluster : String = ENV["BRIGHT_CLUSTER"]? || "app.brightsec.com"
    @output : String
    @update : Bool
    @all_links : Hash(SnykIssue, BrightIssue) = Hash(SnykIssue, BrightIssue).new
    @bright_only_findings : Array(BrightIssue) = Array(BrightIssue).new

    def initialize(@snyk_token, @snyk_org, @snyk_project, @bright_token, @bright_scan = nil, @output = "json", @update = false)
    end

    # Run a verification scan based on the Snyk project findings
    # This will start a scan on Bright, the tests to run will be based on the Snyk findings
    def verification_scan(target : String)
      # validate target
      verified_target = SecTester::Target.new(target)
      snyk_issues = get_snyk_issues
      # translate snyk issues to bright tests
      bright_tests = generate_test_array(snyk_issues)

      # create a new scan
      scan_id = start_bright_scan(target_url: verified_target.url, tests: bright_tests)
      case @output
      when "json"
        print "{\"scan_id\": \"#{scan_id}\"}"
      when "markdown", "ascii"
        puts "Scan ID: #{scan_id}"
      end
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

      bright_issues.each do |bright_issue|
        next if already_linked_ids.includes?(bright_issue.id)
        @bright_only_findings << bright_issue
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
              ## SAST Issue Correlation
              • Source Code File: #{link[0].attributes.primary_file_path}:#{link[0].attributes.primary_region.start_line}:#{link[0].attributes.primary_region.start_column}
              <br>
              • This issue is linked to [Snyk issue #{link[0].id}](#{snyk_issue_url(link[0])})
              <br>
              ![snyk-logo](https://res.cloudinary.com/snyk/image/upload/w_80,h_80/v1537345891/press-kit/brand/avatar-transparent.png)
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
          "Snyk Unique ID",
          "Bright Unique ID",
        ]

        @all_links.each do |link|
          row [
            link[0].attributes.title,
            link[0].attributes.cwe.first,
            "[ID##{link[0].id[0..4]}](#{snyk_issue_url(link[0])})",
            "[ID##{link[1].id[0..4]}](#{bright_issue_url(link[1])})",
          ]
        end

        @bright_only_findings.each do |issue|
          row [
            issue.name,
            issue.cwe,
            "N/A",
            "[ID##{issue.id[0..4]}](#{bright_issue_url(issue)})",
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

    # Start a new scan on Bright
    private def start_bright_scan(tests : Array(String), target_url : String)
      headers = HTTP::Headers{
        "Authorization" => "Api-Key #{@bright_token}",
        "Content-Type"  => "application/json",
        "Accept"        => "application/json",
      }

      bright_url = "https://#{@bright_cluster}/api/v1/scans"

      body = {
        "name":                 "Snyk Verification Scan for project #{@snyk_project}",
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
          return URI.encode_path(org["attributes"]["name"].as_s)
        end
      end

      raise "Failed to find Snyk org name based on given org id"
    end

    # Get specific snyk issue by id
    private def get_snyk_issue_by_id(id : String) : SnykIssue
      url = "https://api.snyk.io/rest/orgs/#{@snyk_org}/code_issue_details/#{id}?project_id=#{@snyk_project}&version=2023-03-21~experimental"
      headers = HTTP::Headers{
        "Accept"        => "application/vnd.api+json",
        "authorization" => "#{@snyk_token}",
      }
      resp = HTTP::Client.get(
        url,
        headers: headers
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to get Snyk issues"
        STDERR.puts resp.body.to_s
        exit(1)
      end
      SnykIssue.from_json(JSON.parse(resp.body.to_s)["data"].to_json)
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Snyk response (get_snyk_issue_by_id): #{e.message}"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end

    # Get Snyk issues
    private def get_snyk_issues : Array(SnykIssue)
      snyk_all_issues_url = "https://api.snyk.io/rest/orgs/#{@snyk_org}/code_issue_summaries?project_id=#{@snyk_project}&version=2023-03-21~experimental&limit=100"
      headers = HTTP::Headers{
        "Accept"        => "application/vnd.api+json",
        "authorization" => "#{@snyk_token}",
      }
      resp = HTTP::Client.get(
        snyk_all_issues_url,
        headers: headers
      )

      unless resp.status.success?
        STDERR.puts "ERROR: Failed to get Snyk issues"
        STDERR.puts resp.body.to_s
        exit(1)
      end

      resp_json_all_issues = JSON.parse(resp.body.to_s)

      # Itirate through all issues and get full details
      snyk_issues = Array(SnykIssue).new
      resp_json_all_issues["data"].as_a.each do |partial_issue|
        snyk_issues << get_snyk_issue_by_id(partial_issue["id"].as_s)
      end

      snyk_issues
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Snyk response (get_snyk_issues): #{e.message}}"
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

    # A method to map snyk issues to bright tests
    private def generate_test_array(snyk_issues : Array(SnykIssue)) : Array(String)
      tests = Array(String).new
      snyk_issues.each do |issue|
        issue.attributes.title.split(" ").each do |word|
          SecTester::SUPPORTED_TESTS.each do |test|
            if test.includes?(word.downcase)
              tests << test
            end
          end
        end
      end
      tests.uniq
    end
  end
end
