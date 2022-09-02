import sys, os

if __name__ == '__main__':

    extra = []
    with open(sys.argv[1]) as f:
        comb2 = {}
        for line in f:
            if "->" in line and "__" not in line and "BRD" not in line:
                quote = line.find("\"")+1
                quote2 = line.find("\"", quote)
                responseStart = line.find("/")
                responseEnd = quote2
                transition = line[:quote]
                transitionOutput = transition, line[responseStart:responseEnd]

                labelInput = line[quote:responseStart] + line[responseStart:responseEnd]
                if transitionOutput in comb2:
                    comb2[transitionOutput] = comb2[transitionOutput] + labelInput + "\\n"
                else:
                    comb2[transitionOutput] = labelInput + "\\n"
            else:
                extra.append(line)
        f.close()

                # label = line[quote:quote2]
                # if transition in comb:
                    # comb[transition] = comb[transition] + "\\n" + label
                # else:
                    # comb[transition] = label

    with open(sys.argv[1], "w") as w:
        for x in extra:
            if "}" not in x and "/ -\"" not in x:
                w.write(x)
        for trans in comb2:
            x = '' + trans[0] + comb2[trans] + "\"];\n"
            w.write(x)
        w.write("}")
