#!/usr/bin/python

import sys
import re

gen_dir = "./autogensrc/"


class DebugUtil:
    def __init__(self, file_name):
        self.file_name = file_name
        self.f = open(self.file_name, "w")
        self.line_num = 0

    def close_file(self):
        self.f.close()

    def inc_line_num(self):
        self.line_num += 1

    def p(self, message):
        new_msg = "@line {0:04d}:> {1}\n".format(self.line_num, message)
        print new_msg,
        self.f.write(new_msg)

    def p_no_line(self, message):
        print message
        self.f.write(message + "\n")


class FuncInfo:
    funcInfoMap = {}

    @staticmethod
    def create_func_info(line, line_num):
        new_func_info = FuncInfo(line)
        key = new_func_info.func_name
        if key in FuncInfo.funcInfoMap:
            orig_line_num = "@line {0:04d}".format(FuncInfo.funcInfoMap[key])
            debug.p_no_line("  *** warning *** found duplicated line. original: " + orig_line_num)
            return None
        else:
            FuncInfo.funcInfoMap[key] = line_num
            return new_func_info

    def __init__(self, line):
        self.line = line
        self.ret_type = ""
        self.func_name = ""
        self.args_decl = []
        self.options = []
        # define parse mode
        in_ret_type = 0
        in_name = 1
        in_arg = 2
        in_option = 3

        parse_mode = in_ret_type
        buf = ""
        buffer_list = []
        bracket_count = 0
        for ch in line:
            if parse_mode == in_ret_type:
                if ch == " ":
                    if buf != "":
                        buffer_list.append(buf)
                        buf = ""
                elif ch == "*":
                    parse_mode = in_name
                    if not buffer_list:
                        debug.p("invalid ret type: " + line)
                        sys.exit(1)
                    count = 0
                    for ret_buf in buffer_list:
                        if count != 0:
                            self.ret_type += " "
                        self.ret_type += ret_buf
                        count += 1
                    self.ret_type += " *"
                    buffer_list = []
                elif ch == "(":
                    parse_mode = in_arg
                    bracket_count += 1
                    if buf != "":
                        buffer_list.append(buf)
                        buf = ""
                    buffer_list_size = len(buffer_list)
                    if buffer_list_size <= 1:
                        debug.p("invalid ret type: " + line)
                        sys.exit(1)
                    count = 0
                    for ret_buf in buffer_list:
                        if count == buffer_list_size - 1:
                            break
                        if count != 0:
                            self.ret_type += " "
                        self.ret_type += ret_buf
                        count += 1
                    self.func_name = buffer_list[buffer_list_size - 1]
                    buffer_list = []
                else:
                    buf += ch
            elif parse_mode == in_name:
                if ch == " ":
                    if buf != "":
                        parse_mode = in_arg
                        self.func_name = buf
                        buf = ""
                elif ch == "(":
                    parse_mode = in_arg
                    bracket_count += 1
                    if buf == "":
                        debug.p("invalid func name: " + line)
                        sys.exit(1)
                    self.func_name = buf
                    buf = ""
                else:
                    buf += ch
            elif parse_mode == in_arg:
                if ch == "(":
                    bracket_count += 1
                elif ch == ")":
                    bracket_count -= 1
                    if bracket_count == 0:
                        parse_mode = in_option
                        self.args_decl = buf.split(", ")
                        buf = ""
                    else:
                        debug.p("invalid args: " + line)
                        sys.exit(1)
                elif ch == " ":
                    if bracket_count != 0:
                        buf += ch
                else:
                    buf += ch
            else:
                if ch == "<":
                    bracket_count += 1
                    buf += ch
                elif ch == ">":
                    bracket_count -= 1
                    buf += ch
                    if bracket_count == 0:
                        self.options.append(buf)
                        buf = ""
                    else:
                        debug.p("invalid option: " + line)
                        sys.exit(1)
                elif ch == " " or ch == "\t":
                    pass
                else:
                    buf += ch

        if not self.options:
            self.options.append("<f:-1>")

    def get_prototype(self):
        proto = self.ret_type + " "
        proto += self.func_name
        proto += "("
        i = 0
        size = len(self.args_decl)
        while i < size:
            if i != 0:
                proto += ", "
            proto += self.args_decl[i]
            i += 1
        proto += ")"
        return proto

    def find_option(self, pattern):
        for option in self.options:
            if option.startswith(pattern):
                found_option = option[0:]
                return found_option
        return None

    def get_args(self):
        args = []
        if len(self.args_decl) == 1 and self.args_decl[0] == "void":
            return ""
        for arg_decl in self.args_decl:
            arg_decl_list = arg_decl.split(" ")
            size = len(arg_decl_list)
            arg = arg_decl_list[size - 1]
            index = 0
            for ch in arg:
                if ch != "*":
                    break
                index += 1
            temp_arg = arg[index:]
            index = 0
            for ch in temp_arg:
                if ch == "[":
                    break
                index += 1
            args.append(temp_arg[0:index])
        return args


class HeaderBuilder:
    def __init__(self, file_name):
        self.file_name = gen_dir + file_name
        self.buf = []
        self.include_name = file_name.split(".")[0].upper() + "_H_"

    def write_head(self, f):
        f.write("#ifndef " + self.include_name + "\n")
        f.write("#define " + self.include_name + "\n")
        f.write("\n")
        f.write("// auto generated header file\n")

    def write_tail(self, f):
        f.write("\n")
        f.write("#endif /* " + self.include_name + " */\n")

    def write_buf(self, f, prefix):
        for element in self.buf:
            f.write(prefix + element)


class HeaderList(HeaderBuilder):
    def __init__(self):
        HeaderBuilder.__init__(self, "headerList.h")

    def parse(self, line):
        header = line.split(" ")[1].strip()
        headerlen = len(header)
        if header[headerlen - 1] == ".":
            temp_header = "#include <" + header[:headerlen - 1] + ">\n"
        elif header[headerlen - 1] == "h":
            temp_header = "#include <" + header + ">\n"
        else:
            debug.p("invalid header :" + header + "\n")
            sys.exit(1)
        if not temp_header in self.buf:
            self.buf.append(temp_header)

    def write_to_file(self):
        debug.p_no_line("write to " + self.file_name)
        f = open(self.file_name, "w")
        HeaderBuilder.write_head(self, f)
        HeaderBuilder.write_buf(self, f, "")
        HeaderBuilder.write_tail(self, f)
        f.close()


class FuncIndex(HeaderBuilder):
    def __init__(self):
        HeaderBuilder.__init__(self, "funcIndex.h")

    def write_to_file(self):
        debug.p_no_line("write to " + self.file_name)
        f = open(self.file_name, "w")
        HeaderBuilder.write_head(self, f)
        f.write("#define FUNC_INDEX(funcname) funcname ## _orig_index\n")
        f.write("\n")
        f.write("typedef enum {\n")
        HeaderBuilder.write_buf(self, f, "\t")
        f.write("\tfunc_index_size\n")
        f.write("} FuncIndex;\n")
        HeaderBuilder.write_tail(self, f)
        f.close()

    def append(self, func_name):
        self.buf.append("FUNC_INDEX(" + func_name + "),\n")


class FuncType(HeaderBuilder):
    def __init__(self):
        HeaderBuilder.__init__(self, "funcType.h")

    def write_to_file(self):
        debug.p_no_line("write to " + self.file_name)
        f = open(self.file_name, "w")
        HeaderBuilder.write_head(self, f)
        HeaderBuilder.write_buf(self, f, "")
        HeaderBuilder.write_tail(self, f)
        f.close()

    def append(self, func_info):
        type_list = []
        for arg_decl in func_info.args_decl:
            arg_type = ""
            arg_decl_list = arg_decl.split(" ")
            size = len(arg_decl_list)
            if size == 1:
                if arg_decl_list[0] == "..." or "void":
                    arg_type = arg_decl_list[0]
                else:
                    debug.p("invalid args decl: " + arg_decl)
                    sys.exit(1)
            elif size >= 2:
                i = 0
                while i < size - 1:
                    if i != 0:
                        arg_type += " "
                    arg_type += arg_decl_list[i]
                    i += 1
                bracket_count = 0
                i = 0
                for ch in arg_decl_list[size - 1]:
                    if ch == "*":
                        if i == 0:
                            arg_type += " "
                        arg_type += ch
                    elif ch == "[":
                        bracket_count += 1
                        if bracket_count != 1:
                            debug.p("invalid args decl: " + arg_decl)
                            sys.exit(1)
                        arg_type += ch
                    elif ch == "]":
                        bracket_count -= 1
                        if bracket_count != 0:
                            debug.p("invalid args decl: " + arg_decl)
                            sys.exit(1)
                        arg_type += ch
                        bracket_count = 0
                    else:
                        if bracket_count == 1:
                            arg_type += ch
                    i += 1
            else:
                debug.p("invalid args decl: " + arg_decl)
                sys.exit(1)
            type_list.append(arg_type)
        cast = "(" + func_info.ret_type + " (*)("
        i = 0
        size = len(type_list)
        while i < size:
            if i != 0:
                cast += ", "
            cast += type_list[i]
            i += 1
        cast += "))\n"
        self.buf.append("#define " + func_info.func_name + "_orig_type " + cast)


class HookFile:
    def __init__(self):
        self.file_name = gen_dir + "hook.c.txt"
        self.buf = []

    def write_to_file(self):
        debug.p_no_line("write to " + self.file_name)
        f = open(self.file_name, "w")
        f.write("// auto generated source file\n")
        for element in self.buf:
            f.write(element)
            f.write("\n")
        f.close()

    @staticmethod
    def create_fail_check(func_info):
        option_f = func_info.find_option("<f:")
        option_s = func_info.find_option("<s:")

        if option_f is not None or option_s is not None:
            if option_f is not None:
                ret = "ret == "
                value = option_f[1:len(option_f) - 1].split(":")[1]
            else:
                ret = "ret != "
                value = option_s[1:len(option_s) - 1].split(":")[1]
            if value != "NULL":
                ret += "(" + func_info.ret_type + ")"
            return ret + value
        debug.p("invalid options: %s" + func_info.options)
        sys.exit(1)

    def append(self, func_info):
        head = func_info.get_prototype() + "\n"

        if func_info.find_option("<stub>") is not None:
            self.buf.append(head + "{\n" + "\t//function stub\n" + "}\n")
            return

        body = ""
        body += "\t" + func_info.ret_type + " ret = CALL_ORIG_FUNC(" + func_info.func_name + ")("
        args = func_info.get_args()
        i = 0
        size = len(args)
        while i < size:
            if i != 0:
                body += ", "
            body += args[i]
            i += 1
        body += ");\n"
        body += "\tif(" + HookFile.create_fail_check(func_info) + ") {\n"
        body += "\t\treportError(errno, \"" + func_info.func_name + "\");\n"
        body += "\t}\n"
        body += "\treturn ret;\n"

        self.buf.append(head + "{\n" + body + "}\n")


debug = DebugUtil("gensrc.log")


def main():
    if len(sys.argv) == 1:
        debug.p_no_line("need target file")
        sys.exit(1)

    pattern = re.compile(".+TODO")
    header_list = HeaderList()
    func_index = FuncIndex()
    func_type = FuncType()
    hook_file = HookFile()

    in_func = False
    target_file = sys.argv[1]
    f = open(target_file, "r")
    debug.p_no_line("open target file: {0}\n".format(target_file))
    lines = f.readlines()
    f.close()

    debug.p_no_line("######################")
    debug.p_no_line("#      Parse File    #")
    debug.p_no_line("######################\n")
    for line in lines:
        debug.inc_line_num()
        line = line.expandtabs(4).strip()
        if not in_func:
            if line.startswith("[h"):
                debug.p("match: [header] {0}".format(line))
                header_list.parse(line)
            elif line.startswith("[f"):
                debug.p("match: [func/]")
                in_func = True
            elif line.startswith("["):
                debug.p("not match: " + line)
            else:
                debug.p("skip unused line: " + line)
        else:
            if line.startswith("[/f"):
                debug.p("match: [/func]")
                in_func = False
            elif line == "" or line == "\t" or line == "\n":
                debug.p("skip empty line")
            elif line.startswith("#") or line.startswith("//") or line.startswith("/*"):
                if pattern.match(line):
                    debug.p("=== TODO === " + line)
                else:
                    debug.p("skip one line comment")
            elif line.startswith("["):
                debug.p("not match: " + line)
            else:
                debug.p("parsing at: {0}".format(line))
                func_info = FuncInfo.create_func_info(line, debug.line_num)
                if func_info is None:
                    continue
                func_index.append(func_info.func_name)
                func_type.append(func_info)
                hook_file.append(func_info)
    # generate files in ./autogensrc/
    debug.p_no_line("\n######################")
    debug.p_no_line("#   Generate Files   #")
    debug.p_no_line("######################\n")
    header_list.write_to_file()
    func_index.write_to_file()
    func_type.write_to_file()
    hook_file.write_to_file()

if __name__ == '__main__':
    main()
