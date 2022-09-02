import os
import sys
import glob
import filecmp

def usage():
    print "runtest.py [-u]"

def dottoxml(fin, fout, ftype="Graphml"):
    os.system("python ../src/dottoxml.py -f %s %s %s" % (ftype, fin, fout))

def createOutName(stem, ftype, update):
    if update:
        return os.path.join(ftype,stem+'.'+ftype)
    else:
        return os.path.join('dot',stem+'.'+ftype)

out_formats = ['Graphml','GML','GDF']

def main():
    update = False
    if len(sys.argv) > 1 and sys.argv[1] == "-u":
        update = True

    dots = glob.glob('dot/*.dot')
    diffs = 0
    for d in dots:
        print d
        head, tail = os.path.split(d)
        fstem = os.path.splitext(tail)[0]
        for f in out_formats:
            fout = createOutName(fstem, f.lower(), update)

            dottoxml(d, fout, f)
            if not update:
                cpath = createOutName(fstem, f.lower(), True)
                if os.path.isfile(cpath):
                    if not filecmp.cmp(fout,cpath,shallow=False):
                        print "Difference in %s -> %s!" % (d, fout)
                        diffs += 1
                else:
                    print "File %s doesn't exist!" % cpath
                    
                os.remove(fout)

    if not update:
        print "\n%d differences found!\n" % diffs

if __name__ == "__main__":
    main()

