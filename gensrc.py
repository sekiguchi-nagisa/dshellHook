#!/usr/bin/python

import sys

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
        bracket_count = 0
        for ch in line:
            if parse_mode == in_ret_type:
                if ch == " ":    # set ret_type
                    parse_mode = in_name
                    self.ret_type = buf
                    buf = ""
                else:            # append to buf
                    buf += ch
            elif parse_mode == in_name:
                if ch == "*":    # add pointer symbol
                    self.ret_type += " " + ch
                elif ch == " ":  # set func_name
                    if buf != "":
                        parse_mode = in_arg
                        self.func_name = buf
                        buf = ""
                else:            # append to buf
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
        for arg_decl in self.args_decl:
            temp = arg_decl.split(" ")
            size = len(temp)
            arg = temp[size - 1]
            if arg.startswith("*"):
                args.append(arg[1:])
            else:
                args.append(arg)
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
            self.buf.append("#include <" + header[:headerlen - 1] + ">\n")
        elif header[headerlen - 1] == "h":
            self.buf.append("#include <" + header + ">\n")
        else:
            debug.p("invalid header :" + header + "\n")
            sys.exit(1)

    def write_to_file(self):
        sorted(set(self.buf), key=self.buf.index)
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
            temp = arg_decl.split(" ")
            size = len(temp)
            if size == 1:
                if temp[0] == "...":
                    arg_type = temp[0]
                else:
                    debug.p("invalid args decl: " + arg_decl)
                    sys.exit(1)
            elif size == 2:
                arg_type = temp[0]
                if temp[1].startswith("*"):
                    arg_type += " *"
            elif size > 2:
                i = 0
                while i < size - 1:
                    if i != 0:
                        arg_type += " "
                    arg_type += temp[i]
                    i += 1
                if temp[size - 1].startswith("*"):
                    arg_type += " *"
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


class SaveFunc:
    def __init__(self):
        self.file_name = gen_dir + "saveFunc.c"
        self.buf = []

    def write_to_file(self):
        debug.p_no_line("write to " + self.file_name)
        f = open(self.file_name, "w")
        f.write("#include \"../utils.h\"\n")
        f.write("\n")
        f.write("// auto generated source file\n")
        f.write("void saveFuncs(void **originalFuncTable)\n")
        f.write("{\n")
        ## write save func
        for element in self.buf:
            f.write("\t" + element)
        f.write("}\n")
        f.close()

    def append(self, func_name):
        self.buf.append("SAVE_FUNC(" + func_name + ");\n")


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
        body += "\t\treportError(errno, NULL);\n"
        body += "\t}\n"
        body += "\treturn ret;\n"

        self.buf.append(head + "{\n" + body + "}\n")


debug = DebugUtil("gensrc.log")


def main():
    if len(sys.argv) == 1:
        debug.p_no_line("need target file")
        sys.exit(1)

    header_list = HeaderList()
    func_index = FuncIndex()
    func_type = FuncType()
    save_func = SaveFunc()
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
            if line.startswith("[header]"):
                debug.p("match: [header] {0}".format(line))
                header_list.parse(line)
            elif line.startswith("[func/]"):
                debug.p("match: [func/]")
                in_func = True
            else:
                debug.p("skip unused line: " + line)
        else:
            if line.startswith("[/func]"):
                debug.p("match: [/func]")
                in_func = False
            elif line == "" or line == "\t" or line == "\n":
                debug.p("skip empty line")
            elif line.startswith("#") or line.startswith("//"):
                debug.p("skip one line comment")
            else:
                debug.p("parsing at: {0}".format(line))
                func_info = FuncInfo(line)
                func_index.append(func_info.func_name)
                func_type.append(func_info)
                save_func.append(func_info.func_name)
                hook_file.append(func_info)
    # generate files in ./autogensrc/
    debug.p_no_line("######################")
    debug.p_no_line("#   Generate Files   #")
    debug.p_no_line("######################\n")
    header_list.write_to_file()
    func_index.write_to_file()
    func_type.write_to_file()
    save_func.write_to_file()
    hook_file.write_to_file()

if __name__ == '__main__':
    main()
