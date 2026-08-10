# The "Advanced" report-builder backend. The panel is a fragment the signup page
# fetches only after the Advanced button is clicked, and this endpoint is
# referenced nowhere else - not in served HTML, not in any nav - so it is only
# discoverable by running the page and interacting with it.
class AdvancedController < ApplicationController
  AGGREGATES = {
    "count" => ->(rows) { rows.length },
    "sum"   => ->(rows) { rows.sum { |r| r[:n] } },
    "max"   => ->(rows) { rows.map { |r| r[:n] }.max || 0 },
  }.freeze

  def report
    rows = Post.limit(20).each_with_index.map { |p, i| { id: p.id, title: p.title, n: i + 1 } }

    if params[:agg].present?
      # NEAR-MISS NM-AGG-001: the same "let the caller choose the computation"
      # idea, resolved through a fixed allow-list of named aggregates. An unknown
      # name is rejected, never evaluated. Not a bug.
      fn = AGGREGATES[params[:agg].to_s]
      return render(json: { error: "unknown aggregate" }, status: :bad_request) unless fn

      return render json: { agg: params[:agg], value: fn.call(rows) }
    end

    formula = params[:formula].to_s
    return render(json: { error: "formula or agg required" }, status: :bad_request) if formula.empty?

    # FIXED CODEINJ-001: the "computed column" is resolved through a fixed set of
    # named projections instead of being evaluated. A formula the server does not
    # recognise is rejected, never run, so the request body cannot smuggle in code.
    columns = {
      "row[:title].length" => ->(row) { row[:title].length },
      "row[:n]"            => ->(row) { row[:n] },
      "row[:id]"           => ->(row) { row[:id] },
    }
    project = columns[formula]
    return render(json: { error: "unknown column" }, status: :bad_request) unless project

    computed = rows.map { |row| { id: row[:id], value: project.call(row) } }
    render json: { formula: formula, computed: computed }
  end
end
