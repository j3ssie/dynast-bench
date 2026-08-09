require "erb"

class ImportProbe
  attr_accessor :template

  def result(view_binding)
    ERB.new(template.to_s).result(view_binding)
  end
end
