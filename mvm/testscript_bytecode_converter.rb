require 'fileutils'

def convert_to_bytecode(file)
  iseq = RubyVM::InstructionSequence.compile_file("testscripts/" + file)
  dumped = Marshal.dump(iseq.to_a)
  bc_file = File.new("testscripts/binarycode/" + file + ".bin", 'w')
  bc_file.write(dumped)
  bc_file.close()
end

FileUtils.mkdir_p("testscripts/binarycode/")

Dir.glob('testscripts/*.rb') do |rb_file|
  convert_to_bytecode(File.basename(rb_file))
end
