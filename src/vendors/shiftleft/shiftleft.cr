require "./shiftleft_issue.cr"

module Issue::Linker
  class ShiftLeft
    getter name : String = "ShiftLeft (QWIET)"

    # The organization ID
    getter org_id : String  # this is usually a UUID
    getter app_id : String  # this is usually a String of the app name (like "brokencrystals")
    getter api_key : String # this is usually a JWT token

    def initialize(@org_id : String, @app_id : String, @api_key : String)
    end

    def issue_url(id : String) : String
      "https://app.shiftleft.io/apps/#{@app_id}/findings/vulnerabilities?findingId=#{id}"
    end

    def get_issues : Array(ShiftLeftIssue)
      issue_array = Array(ShiftLeftIssue).new
      page = 1

      # Make first Call
      resp = HTTP::Client.get(
        url: issues_url,
        headers: get_headers
      )

      parsed_response = ShiftLeftResponse.from_json(resp.body)

      unless resp.status_code == 200
        STDERR.puts("ShiftLeft API returned a non-200 status code: #{resp.status_code} with body: #{resp.body}")
        exit(1)
      end

      issue_array.concat(parsed_response.response.findings)
      while parsed_response.response.has_more
        page += 1
        resp = HTTP::Client.get(
          url: issues_url(page),
          headers: get_headers
        )

        parsed_response = ShiftLeftResponse.from_json(resp.body)

        unless resp.status_code == 200
          STDERR.puts("ShiftLeft API returned a non-200 status code: #{resp.status_code} with body: #{resp.body}")
          exit(1)
        end

        issue_array.concat(parsed_response.response.findings)
      end
      issue_array = issue_array.reject { |issue| issue.type != "vuln" }
      issue_array
    rescue e : JSON::ParseException
      STDERR.puts "ERROR: Failed to parse Shiftleft response (get_issues): #{e.message}}"
      STDERR.puts resp.try &.body.to_s
      exit(1)
    end

    private def issues_url(page : Int32 = 1) : String
      "https://app.shiftleft.io/api/v4/orgs/#{@org_id}/apps/#{@app_id}/findings?type=vuln&per_page=249&page=#{page}"
    end

    private def get_headers : HTTP::Headers
      # Expecting auth like:
      # Authorization: Bearer {access token}
      # Required scopes: findings:list
      HTTP::Headers{
        "Authorization" => "Bearer #{@api_key}",
        "Content-Type"  => "application/json",
      }
    end
  end
end
