module Issue::Linker
  class Link
    @vendor : Vendor
    @bright : Bright
    @output : String
    @update : Bool

    @all_links : Hash(VendorIssue, BrightIssue) = Hash(VendorIssue, BrightIssue).new
    @bright_only_findings : Array(BrightIssue) = Array(BrightIssue).new

    def initialize(@vendor : Vendor, @bright : Bright, @output : String = "json", @update : Bool = false)
    end

    # Link Vendor issues to Bright issues
    # This is done by comparing cwe and issue names
    def link
      case @vendor
      when Snyk
        link_snyk
      when CX
        link_cx
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
      @all_links.each do |vendor_issue, bright_issue|
        source_file = case vendor_issue
                      when SnykIssue
                        "#{vendor_issue.attributes.primary_file_path}:#{vendor_issue.attributes.primary_region.start_line}:#{vendor_issue.attributes.primary_region.start_column}"
                      when CXIssue
                        "#{vendor_issue.nodes.first.file_name}:#{vendor_issue.nodes.first.line}:#{vendor_issue.nodes.first.column}"
                      else
                        raise "Unknown vendor #{vendor_issue.class}"
                      end

        issue_url = case vendor_issue
                    when SnykIssue
                      "[Snyk issue #{vendor_issue.id}](#{@vendor.as(Snyk).issue_url(vendor_issue)})"
                    when CXIssue
                      "[Checkmarx issue #{vendor_issue.result_hash}](#{@vendor.as(CX).issue_url(vendor_issue)})"
                    else
                      raise "Unknown vendor #{vendor_issue.class}"
                    end

        vendor_logo = case vendor_issue
                      when SnykIssue
                        "![snyk-logo](https://res.cloudinary.com/snyk/image/upload/w_80,h_80/v1537345891/press-kit/brand/avatar-transparent.png)"
                      when CXIssue
                        "![cx-logo](https://checkmarx.com/wp-content/uploads/2021/04/CHeckmarx-Logo-2.png)"
                      else
                        raise "Unknown vendor #{vendor_issue.class}"
                      end

        @bright.update(bright_issue, source_file, issue_url, vendor_logo)
      end
    end

    def verification_scan(target : String)
      tests = generate_test_array(@vendor.get_issues)
      scan_id = @bright.verification_scan(target: target, issues: tests)
      case @output
      when "json"
        print "{\"scan_id\": \"#{scan_id}\"}"
      when "markdown", "ascii"
        puts "Scan ID: #{scan_id}"
      end
    end

    private def output_json
      links = Array(Hash(String, Hash(String, Array(String) | String) | Hash(String, String)) | Hash(String, Hash(String, String))).new
      @all_links.each do |k, v|
        links << case k
        when SnykIssue
          {
            "#{@vendor.name.downcase}_issue" => {
              "title" => k.attributes.title,
              "cwe"   => k.attributes.cwe,
              "url"   => @vendor.as(Snyk).issue_url(k),
            },
            "bright_issue" => {
              "name" => v.name,
              "cwe"  => v.cwe,
              "url"  => @bright.issue_url(v),
            },
          }
        when CXIssue
          {
            "#{@vendor.name.downcase}_issue" => {
              "title" => k.query_name,
              "cwe"   => "CWE-#{k.cwe_id}",
              "url"   => @vendor.as(CX).issue_url(k),
            },
            "bright_issue" => {
              "name" => v.name,
              "cwe"  => v.cwe,
              "url"  => @bright.issue_url(v),
            },
          }
        else
          raise "Unknown vendor #{k.class}"
        end
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
          case link[0]
          when SnykIssue
            snyk_issue = link[0].as(SnykIssue)
            row [
              snyk_issue.attributes.title,
              snyk_issue.attributes.cwe.first,
              "[ID##{snyk_issue.id[0..4]}](#{@vendor.as(Snyk).issue_url(snyk_issue)})",
              "[ID##{link[1].id[0..4]}](#{@bright.issue_url(link[1])})",
            ]
          when CXIssue
            cx_issue = link[0].as(CXIssue)
            row [
              cx_issue.query_name,
              "CWE-#{cx_issue.cwe_id}",
              "[ID##{cx_issue.result_hash}](#{@vendor.as(CX).issue_url(cx_issue)})",
              "[ID##{link[1].id[0..4]}](#{@bright.issue_url(link[1])})",
            ]
          end
        end

        @bright_only_findings.each do |issue|
          row [
            issue.name,
            issue.cwe,
            "N/A",
            "[ID##{issue.id[0..4]}](#{@bright.issue_url(issue)})",
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

    # A method to map vendor issues to bright tests
    private def generate_test_array(vendor_issues : Array(VendorIssue)) : Array(String)
      tests = Array(String).new
      vendor_issues.each do |issue|
        case issue
        when SnykIssue
          issue.attributes.title.split(" ").each do |word|
            SecTester::SUPPORTED_TESTS.each do |test|
              if test.includes?(word.downcase)
                tests << test
              end
            end
          end
        when CXIssue
          issue.query_name.split("_").each do |word|
            SecTester::SUPPORTED_TESTS.each do |test|
              if test.includes?(word.downcase)
                tests << test
              end
            end
          end
        end
      end
      tests.uniq
    end

    private def link_cx
      cx_issues = @vendor.get_issues.as(Array(CXIssue))
      bright_issues = @bright.get_bright_issues
      already_linked_ids = Array(String).new

      cx_issues.each do |cx_issue|
        bright_issues.each do |bright_issue|
          if "CWE-#{cx_issue.cwe_id}" == bright_issue.cwe || (cx_issue.query_name.includes?(bright_issue.name) || bright_issue.name.includes?(cx_issue.query_name))
            next if already_linked_ids.includes?(bright_issue.id) || already_linked_ids.includes?(cx_issue.result_hash)
            @all_links[cx_issue] = bright_issue
            already_linked_ids << bright_issue.id
            already_linked_ids << cx_issue.result_hash
          end
        end
      end

      bright_issues.each do |bright_issue|
        next if already_linked_ids.includes?(bright_issue.id)
        @bright_only_findings << bright_issue
      end
    end

    private def link_snyk
      snyk_issues = @vendor.get_issues.as(Array(SnykIssue))
      bright_issues = @bright.get_bright_issues
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
    end
  end
end
