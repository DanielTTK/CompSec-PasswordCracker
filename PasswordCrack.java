import java.io.*;
import java.util.*;
import java.util.function.Function;

public class PasswordCrack {

    static class PasswordLine {
        String account;
        String salt;            // first 2 chars ofencrypted data
        String hash;            // encrypted pass data
        String gcosField;       // "First Last"
        boolean crack;          // if cracked or not

        PasswordLine(String account, String salt, String hash, String gcosField) {
            this.account    = account;
            this.salt       = salt;
            this.hash       = hash;
            this.gcosField  = gcosField;
            this.crack      = false;
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Usage: java PasswordCrack <dictionary> <passwd>");
            System.exit(1);
        }
        if (!(args[0].contains(".txt"))){
            System.err.println("Dictionary should be a .txt file (got: " + args[0] + ")");
            System.exit(1);
        }
        if (!(args[1].contains(".txt"))){
            System.err.println("Passwd file should be a .txt file (got: " + args[1] + ")");
            System.exit(1);
        }

        // Check that input files actually exist and are readable
        File dictFile = new File(args[0]);
        if (!dictFile.exists() || !dictFile.isFile() || !dictFile.canRead()) {
            System.err.println("Dictionary file not found or not readable: " + args[0]);
            System.exit(1);
        }
        File passwdFile = new File(args[1]);
        if (!passwdFile.exists() || !passwdFile.isFile() || !passwdFile.canRead()) {
            System.err.println("Passwd file not found or not readable: " + args[1]);
            System.exit(1);
        }

        ArrayList<PasswordLine> entries = parsePasswdFile(args[1]);
        ArrayList<String> dict = null;

        dict = buildDictonary(args[0]);
        dict = addUserInfoToDictonary(entries, dict);
        dict.add(""); // add empty for numeric base

        String suffix = "";
        for(int c=1;c<9;c++){
            suffix += c;
            dict.add(suffix);
        }

        // test raw dict
        runMangleType(entries, dict, word -> Arrays.asList(word));

        // list of all mangle type functions
        List<Function<String, List<String>>> singleMangles = Arrays.asList(
            lowerCaseMangle, upperCaseMangle, capitalizeMangle, notCapitalizeMangle,
            deleteLastCharMangle, deleteFirstCharMangle,
            reverseMangle, appendReverseMangle, appendCapitalizedReverseMangle,
            leetMangle, capitalizeEveryOtherMangle, wordSuffixMangle, 
            appendCommonNumbersMangle, appendCharMangle,
            prependCharMangle, suffixMangle, fourDigitYearMangle, appendTwoDigitsMangle
        );

        // single mangles
        for (int m = 0; m < singleMangles.size(); m++) {
            runMangleType(entries, dict, singleMangles.get(m));
        }


        // double mangles
        // Test all, other than second mangle last 5
        execMangles(
            0, 
            0, 
            0, 
            5, 
            singleMangles, entries, dict
        );

        // Test only last 5 second mangles with all first mangles
        execMangles(
            0, 
            0, 
            singleMangles.size() - 5, 
            0, 
            singleMangles, entries, dict
        );
    }

    private static void execMangles
    (int singleMangleStart, 
        int singleMangleEndOffset, 
        int sncdMangleStart, 
        int scndMangleEndOffset, 
        List<Function<String, List<String>>> singleMangles, 
        ArrayList<PasswordLine> entries, 
        ArrayList<String> dict
    ){
        for (int i = singleMangleStart; i < singleMangles.size() - singleMangleEndOffset; i++) {
            for (int j = sncdMangleStart; j < singleMangles.size() - scndMangleEndOffset; j++) {
                if (i == j) continue;
                if ((i == 0 || i == 1) && (j == 0 || j == 1)) continue;
                if ((i == 2 || i == 3) && (j == 2 || j == 3)) continue;
                if ((i >= 13) && (j >= 13)) continue;

                runMangleType(entries, dict, doubleMangle(singleMangles.get(i), singleMangles.get(j)));
            }
        }
    }

    static Function<String, List<String>> doubleMangle
    (Function<String, List<String>> mangleOne, Function<String, List<String>> mangleTwo) {
        return word -> {
            List<String> mangles = new ArrayList<>();
            List<String> firstMangles = mangleOne.apply(word);
            if (firstMangles == null || firstMangles.isEmpty()) return mangles;
            for (int i = 0; i < firstMangles.size(); i++) {
                List<String> secondMangles = mangleTwo.apply(firstMangles.get(i));
                if (secondMangles != null && !secondMangles.isEmpty()) {
                    mangles.addAll(secondMangles);
                }
            }
            return mangles;
        };
    }

    static Function<String, List<String>> wordSuffixMangle = word -> {
        if (word.length() >= 7) return Collections.emptyList();
        return Arrays.asList(
            word + "ing", word + "ed", word + "er", word + "ers", word + "e",
            word + "ism", word + "ist", word + "tion", word + "is", word + "ting",
            word + "rian",word + "arian", word + "itarian", word + "lent",
            word + "etarian", word + "ness", word + "ment", word + "ian", 
            word + "ianity", word + "ly", word + "es"
        );
    };

    static Function<String, List<String>> appendCommonNumbersMangle = word -> {
        if (word == null || word.isEmpty() || word.length() >= 7) return Collections.emptyList();
        List<String> mangles = new ArrayList<>();
        String[] commonNumbers = {"00", "01", "12", "19", "20", "99", 
                                "123", "1234", "12345", "111", "222"};
        for(int i=0;i<commonNumbers.length;i++){
            String mangle = word + commonNumbers[i];
            mangles.add(mangle);
        }
        return mangles;
    };

    static Function<String, List<String>> appendCapitalizedReverseMangle = word -> {
        if (word == null || word.isEmpty()) return Collections.emptyList();
        List<String> mangles = new ArrayList<>();
        String capitalized = word.substring(0, 1).toUpperCase() + word.substring(1);
        String mangle = new StringBuilder(capitalized).reverse().toString();
        mangles.add(capitalized + mangle);
        mangles.add(mangle + capitalized);
        return mangles;
    };

    static Function<String, List<String>> appendReverseMangle = word -> {
        if (word == null || word.isEmpty()) return Collections.emptyList();
        List<String> mangles = new ArrayList<>();
        String mangle = new StringBuilder(word).reverse().toString();
        mangles.add(word + mangle);
        mangles.add(mangle + word);
        return mangles;
    };

    static Function<String, List<String>> reverseMangle = word -> {
        if (word == null) return Collections.emptyList();
        String mangle = new StringBuilder(word).reverse().toString();
        return Arrays.asList(mangle);
    };

    static Function<String, List<String>> lowerCaseMangle = word -> {
        return applyAlphabeticalMangle(w -> w.toLowerCase()).apply(word);
    };
    static Function<String, List<String>> upperCaseMangle = word -> {
        return applyAlphabeticalMangle(w -> w.toUpperCase()).apply(word);
    };
static Function<String, List<String>> notCapitalizeMangle = word -> {
        if (word == null || word.length() == 0) return Arrays.asList(word);
        return applyAlphabeticalMangle(w -> w.substring(0, 1).toLowerCase() + w.substring(1).toUpperCase()).apply(word);
    };
    static Function<String, List<String>> capitalizeMangle = word -> {
        if (word == null || word.length() == 0) return Arrays.asList(word);
        return applyAlphabeticalMangle(w -> w.substring(0, 1).toUpperCase() + w.substring(1).toLowerCase()).apply(word);
    };
    static Function<String, List<String>> deleteLastCharMangle = word -> {
        if (word == null) return Collections.emptyList();
        if (word.length() == 0) return Arrays.asList(word);
        if (word.length() > 8) return Collections.emptyList();
        return applyAlphabeticalMangle(w -> w.substring(0, w.length() - 1)).apply(word);
    };
    static Function<String, List<String>> deleteFirstCharMangle = word -> {
        if (word == null || word.length() == 0) return Arrays.asList(word);
        return applyAlphabeticalMangle(w -> w.substring(1)).apply(word);
    };

    /**
     * Helper function that transforms a string based on mangle type. Used to avoid duplicating code.
     * @param transform
     * @return
     * @see <a href="https://docs.oracle.com/javase/8/docs/api/java/util/function/Function.html">Link to Function function info</a>
     * @see <a href="https://www.geeksforgeeks.org/java/function-interface-in-java/">Additional link used for reference</a>
     * @see <a href="https://docs.oracle.com/javase/8/docs/api/java/util/Arrays.html#asList-T...-">Additional link used for reference</a>
     * 
     */
    private static Function<String, List<String>> applyAlphabeticalMangle(Function<String, String> mangle) {
    return word -> { 
        if (word == null || word.isEmpty()) return Collections.emptyList();
        return Arrays.asList(mangle.apply(word)); };
}

    static Function<String, List<String>> suffixMangle = word -> {
        if (word == null) return Collections.emptyList();
        if (word.length() >= 6) return Collections.emptyList();

        List<String> suffixes = new ArrayList<>();
        List<String> mangles = new ArrayList<>();
        String suffix = "";
        int max = 8 - word.length();

        for(int c=1;c<max;c++){
            suffix += c;
            suffixes.add(suffix);
        }
        suffix = "";
        for(int c=max-1;c>=0;c--){
            suffix += c;
            suffixes.add(suffix);
        }
        suffix = "";
        for(int c=1;c<10;c++){
            suffix = String.format("%d%d%d", c, c, c);
            suffixes.add(suffix);
        }
        
        for(int s=0;s<suffixes.size();s++){
            String mangle = word + suffixes.get(s);
            mangles.add(mangle);
        }

        return mangles;
    };

    static Function<String, List<String>> leetMangle = word -> {
        List<String> mangles = new ArrayList<>();
        String mangle = word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
                            .replace('A', '4').replace('E', '3').replace('I', '1').replace('O', '0')
                            .replace('l', '1').replace('s', '5').replace('t', '7')
                            .replace('L', '1').replace('S', '5').replace('T', '7');
        mangles.add(mangle);
        return mangles;
    };


    static Function<String, List<String>> fourDigitYearMangle = word -> {
        if (word == null || word.length() >= 6) return Collections.emptyList();
        List<String> mangles = new ArrayList<>();
        for(int y=1950;y<2026;y++){
            String mangle = word + y;
            mangles.add(mangle);
        }

        return mangles;
    };

    static Function<String, List<String>> appendTwoDigitsMangle = word -> {
        if (word == null || word.length() > 6) return Collections.emptyList();
        List<String> mangles = new ArrayList<>();
        // test "00","01","12","99" first.
        String[] prioDigits = {"00", "01", "12", "99"};
        for(int i=0;i<4;i++){
            String mangle = word + prioDigits[i];
            mangles.add(mangle);
        }
        // test 2-98
        for(int d=2;d<99;d++){
            String mangle = word + String.format("%02d", d);
            mangles.add(mangle);
        }

        return mangles;
    };

    static Function<String, List<String>> capitalizeEveryOtherMangle = word -> {
        if (word == null) return Collections.emptyList();
        List<String> mangles = new ArrayList<>();
        StringBuilder sb = new StringBuilder(word);
        for (int i = 0; i < sb.length(); i++) {
            if (i % 2 == 0) {
                sb.setCharAt(i, Character.toUpperCase(sb.charAt(i)));
            } else {
                sb.setCharAt(i, Character.toLowerCase(sb.charAt(i)));
            }
        }
        mangles.add(sb.toString());

        sb = new StringBuilder(word);
        for (int i = 0; i < sb.length(); i++) {
            if (i % 2 == 0) {
                sb.setCharAt(i, Character.toLowerCase(sb.charAt(i)));
            } else {
                sb.setCharAt(i, Character.toUpperCase(sb.charAt(i)));
            }
        }
        mangles.add(sb.toString());

        return mangles;
    };


    private static ArrayList<String> addUserInfoToDictonary(ArrayList<PasswordLine> entries, ArrayList<String> dict){
        PasswordLine entry = null;    
        for(int i = 0; i < entries.size(); i++){
            entry = entries.get(i);
            dict = addToDictonary(entry, dict);
        }
        return dict;
    }

    /**
     * Runs a particular mangle type function on the dictonary for all password entries
     * @param entries
     * @param dict
     * @param mangleType
     */
    private static void runMangleType(
        ArrayList<PasswordLine> entries, ArrayList<String> dict, 
        Function<String, List<String>> mangleType){
        List<String> mangles = null;
        for(int w = 0; w < dict.size(); w++) {
            mangles = mangleType.apply(dict.get(w));

            for(int c = 0; c < mangles.size(); c++) {
                for(int e = 0; e < entries.size(); e++) {
                    if(!entries.get(e).crack) 
                        checkEntry(entries.get(e), mangles.get(c));
                }
            }
        }
    }

    private static ArrayList<String> addToDictonary(PasswordLine entry, ArrayList<String> dict){
        if (dict == null) {
            System.err.println("Dictionary is null in 'addToDictonary'");
            System.exit(1);
        }

        if (entry != null && entry.account != null && !entry.account.isEmpty())
            dict.add(entry.account);

        if (entry != null && entry.gcosField != null) {
            String[] parts = entry.gcosField.trim().split("\\s+");
            if (parts.length >= 1 && parts[0] != null && !parts[0].isEmpty())
                dict.add(parts[0]);
            if (parts.length >= 2 && parts[1] != null && !parts[1].isEmpty())
                dict.add(parts[1]);
        }

        return dict;
    }


    static Function<String, List<String>> appendCharMangle = word -> {
        return checkMangleAddChar(word, true);
    };

    static Function<String, List<String>> prependCharMangle = word -> {
        return checkMangleAddChar(word, false);
    };


    /**
     * Mangle that adds a char to the beginning or end of the word. Uses all alphabetic and numerical chars.
     * @param word
     * @param append true if char should be appended, false if char should be prepended
     */
    private static List<String> checkMangleAddChar(String word, boolean append){
        String mangle = null;
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        char[] charArray = chars.toCharArray();
        List<String> mangles = new ArrayList<>();

        for(int c=0;c<charArray.length;c++){
            mangle = (append) ? (word + charArray[c]) : charArray[c] + word;
            mangles.add(mangle);
        }
        
        return mangles;
    }

    /**
     * Checks entry hash to hashed word/mangle
     * @param entry 
     * @param word raw word from dictonary usually
     * @param mangle If null, raw word is used
     */
    private static void checkEntry(PasswordLine entry, String word){
        String encrypted = jcrypt.crypt(entry.salt, word);
        if (encrypted.equals(entry.hash)){
            System.out.println(word);
            //writeToFile("passwd2-plain.txt", word);
            entry.crack = true;
        }
    }


    @SuppressWarnings("unused")
    private static void writeToFile(String file, String s){
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file, true))) {
            bw.write(s);
            bw.newLine();
        } catch (IOException e) {
            System.err.println("Failed writing to file " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * This function parses the long dictonary into an arraylist.
     * @param dictFile
     * @param line
     * @return dictonary.
     * 
     * @see <a href="https://stackoverflow.com/questions/5343689/java-reading-a-file-into-an-arraylist">Link to source of code inspiration</a>
     */
    private static ArrayList<String> buildDictonary(String dictFile){
        try {
            if (dictFile == null || dictFile.isEmpty()) {
                System.err.println("Dictionary file path is null or empty in 'buildDictonary'");
                System.exit(1);
            }
            
            Scanner scan = new Scanner(new File(dictFile));
            ArrayList<String> list = new ArrayList<String>();
            while (scan.hasNext()){
                list.add(scan.next());
            }

            scan.close();
            
            return list;

        } catch (IOException e) {
            System.err.println("Failed to read dictionary file '" + dictFile + "': " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
        return new ArrayList<>();
    }

    /**
     * This function parses the password file lines into a arraylist of "PasswordLine" objects
     * @param filename
     * @return
     * @throws IOException
     *
     * @see <a href="https://stackoverflow.com/questions/16104616/using-bufferedreader-to-read-text-file">Link to source of code inspiration</a>
     */
    private static ArrayList<PasswordLine> parsePasswdFile(String filename) throws IOException {
        ArrayList<PasswordLine> entries = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            String encrypt = null;
            String salt = null;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length >= 5) {
                    encrypt = parts[1];
                    salt = encrypt.substring(0, 2);
                    entries.add(new PasswordLine(parts[0], salt, encrypt, parts[4]));
                } else {
                    System.err.println("Failed parsing entry ");
                    System.exit(1);
                }
            }
        } catch (FileNotFoundException e) {
            System.err.println("Passwd file not found " + filename);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Failed reading passwd file " + e.getMessage());
            System.exit(1);
        }
        return entries;
    }
}
