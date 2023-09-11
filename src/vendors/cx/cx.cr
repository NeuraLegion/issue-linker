require "./cx_issue.cr"

module Issue::Linker
  class CX
    getter name : String = "Checkmarx"

    @cx_token : String
    @cx_scan : String # scan id
    @project_id : String

    def initialize(token, @cx_scan, realm : String? = nil, mfa : Bool = false)
      if mfa
        # Convert token to Bearer
        raise "Realm must be provided when using MFA" if realm.nil?
        @cx_token = get_bearer(token, realm)
      else
        @cx_token = token
      end
      @project_id = get_project_id
    end

    def get_issues : Array(CXIssue)
      issues = Array(CXIssue).new
      url = URI.new(
        scheme: "https",
        host: "ast.checkmarx.net",
        path: "/api/sast-results",
        query: URI::Params.new({
          "scan-id"       => [@cx_scan],
          "include-nodes" => ["true"],
          "limit"         => ["10000"],
          "offset"        => ["0"],
          "state"         => ["TO_VERIFY,PROPOSED_NOT_EXPLOITABLE,CONFIRMED,URGENT,NOT_EXPLOITABLE"],
          "severity"      => ["HIGH,MEDIUM,LOW,INFO"],
        })
      )

      headers = HTTP::Headers{
        "Accept"        => "application/json",
        "Authorization" => "#{@cx_token}",
      }

      response = HTTP::Client.get(url, headers)
      CXIssueResponse.from_json(response.body.to_s).results
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse CX response (get_issues): #{e.message}}"
      STDERR.puts response.try &.body.to_s
      exit(1)
    end

    def issue_url(issue : CXIssue) : String
      "https://ast.checkmarx.net/results/#{@cx_scan}/#{@project_id}/sast?result-id=#{URI.encode_www_form(issue.result_hash)}&redirect=true"
    end

    private def get_bearer(token : String, realm : String)
      params = URI::Params.new({
        "grant_type"    => ["refresh_token"],
        "client_id"     => ["ast-app"],
        "refresh_token" => ["#{token}"],
      }).to_s

      uri = URI.new(
        scheme: "https",
        host: "iam.checkmarx.net",
        path: "/auth/realms/#{realm}/protocol/openid-connect/token"
      )

      resp = HTTP::Client.post(
        url: uri,
        body: params,
        headers: HTTP::Headers{
          "Content-Type" => "application/x-www-form-urlencoded",
        }
      )

      JSON.parse(resp.body.to_s)["access_token"].as_s
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse CX response (get_bearer): #{e.message}}"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end

    private def get_project_id : String
      resp = HTTP::Client.get(
        "https://ast.checkmarx.net/api/scans/#{@cx_scan}",
        headers: HTTP::Headers{
          "Accept"        => "application/json",
          "Authorization" => "#{@cx_token}",
        }
      )

      parsed = JSON.parse(resp.body.to_s)
      parsed["projectId"].as_s
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse CX response (get_project_id): #{e.message}}"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end
  end
end
