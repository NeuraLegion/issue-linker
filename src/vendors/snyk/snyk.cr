require "./snyk_issue.cr"

module Issue::Linker
  class Snyk
    getter name : String = "Snyk"

    @snyk_token : String
    @snyk_org : String
    @snyk_project : String

    def initialize(@snyk_token, @snyk_org, @snyk_project)
    end

    def issue_url(issue : SnykIssue) : String
      org_name = org_name(@snyk_org)
      "https://app.snyk.io/org/#{org_name}/project/#{@snyk_project}#issue-#{issue.id}"
    end

    # translate snyk org id to org name
    def org_name(id : String) : String
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
    def get_issue_by_id(id : String) : SnykIssue
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
    def get_issues : Array(SnykIssue)
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
        snyk_issues << get_issue_by_id(partial_issue["id"].as_s)
      end

      snyk_issues
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Snyk response (get_snyk_issues): #{e.message}}"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end
  end
end
