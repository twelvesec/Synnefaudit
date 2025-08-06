package com.twelvesec.cloudscan;

import java.time.Duration;
import java.util.List;

import com.twelvesec.cloudscan.CloudCheck.CheckSummary;

public class ReportPrinter {
    protected static final String CHECKS_SUMMARY = "Checks Summary";
    protected static final String FINAL_REPORT = "Final Report";

    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String PASTEL_GREEN = "\u001B[38;5;157m";
    private static final String PASTEL_RED = "\u001B[38;5;210m";
    private static final String PASTEL_ORANGE = "\u001B[38;5;223m";
    private static final String PASTEL_YELLOW = "\u001B[38;5;229m";
    private static final String PASTEL_BLUE = "\u001B[38;5;153m";
    private static final String PASTEL_PURPLE = "\u001B[38;5;183m";
    private static final String PASTEL_GRAY = "\u001B[38;5;250m";
    
    private static final String CHECKMARK = "[V]";
    private static final String X_MARK = "[X]";
    private static final String WARNING = "[!]";
    private static final String VERTICAL_LINE = "│";
    private static final String HORIZ_LINE = "─";
    private static final String TOP_CONNECT = "┬";
    private static final String MID_BEG_CONNECT = "├";
    private static final String MID_END_CONNECT = "┤";
    private static final String CROSS_CONNECT = "┼";
    private static final String BOTTOM_CONNECT = "┴";
    private static final String BLOCK = "#";
    private static final String SPACE = " ";

    protected void printIndividualStatus(CheckSummary cs) {
        String icon = cs.exceptionCount() > 0
                    ? PASTEL_YELLOW + WARNING + RESET
                    : cs.failCount() > 0
                        ? PASTEL_RED + X_MARK + RESET
                        : cs.passCount() > 0
                            ? PASTEL_GREEN + CHECKMARK + RESET
                            : PASTEL_GRAY + CHECKMARK + RESET;
        String category = String.format("%-24s", cs.category());

        String pass = cs.passCount() > 0
            ? PASTEL_GREEN + String.format("%3d", cs.passCount()) + RESET
            : PASTEL_GRAY + String.format("%3d", cs.passCount()) + RESET;
        String fail = cs.failCount() > 0
            ? PASTEL_RED   + String.format("%5d", cs.failCount()) + RESET
            : PASTEL_GRAY + String.format("%5d", cs.failCount()) + RESET;
        String exce = cs.exceptionCount() > 0
            ? PASTEL_YELLOW+ String.format("%5d", cs.exceptionCount()) + RESET
            : PASTEL_GRAY + String.format("%5d", cs.exceptionCount()) + RESET;
        String nappl = cs.exceptionCount() > 0
            ? PASTEL_YELLOW+ String.format("%6d", cs.napplicableCount()) + RESET
            : PASTEL_GRAY + String.format("%6d", cs.napplicableCount()) + RESET;

        String crit = cs.criticalCount() > 0
            ? PASTEL_RED+ String.format("%3d", cs.criticalCount()) + RESET
            : PASTEL_GRAY + String.format("%3d", cs.criticalCount()) + RESET;
        String high = cs.highCount() > 0
            ? PASTEL_ORANGE+ String.format("%4d", cs.highCount()) + RESET
            : PASTEL_GRAY + String.format("%4d", cs.highCount()) + RESET;
        String med  = cs.mediumCount() > 0
            ? PASTEL_YELLOW+ String.format("%5d", cs.mediumCount()) + RESET
            : PASTEL_GRAY + String.format("%5d", cs.mediumCount()) + RESET;
        String low  = cs.lowCount() > 0
            ? PASTEL_BLUE+ String.format("%4d", cs.lowCount()) + RESET
            : PASTEL_GRAY + String.format("%4d", cs.lowCount()) + RESET;
        String info = cs.infoCount() > 0
            ? PASTEL_PURPLE+ String.format("%3d", cs.infoCount()) + RESET
            : PASTEL_GRAY + String.format("%3d", cs.infoCount()) + RESET;

        System.out.printf(
            " %s %s " +  VERTICAL_LINE + "%s %s %s %s  " + VERTICAL_LINE + "%s %s %s %s %s%n",
            icon, category,
            pass, fail, exce, nappl,
            crit, high, med, low, info
        );
    }
    
    protected void printSectionHeader(String title) {
        String headerFormat = PASTEL_PURPLE + "%-30s" + RESET + VERTICAL_LINE +
                            PASTEL_GREEN + "%5s " + RESET +
                            PASTEL_RED + "%5s " + RESET +
                            PASTEL_YELLOW + "%5s " + RESET +
                            "%6s" +
                            "%5s %4s %4s %4s %4s" + "\n";
        
        System.out.println("\n" + PASTEL_PURPLE + "=".repeat(80) + RESET);
        System.out.println(PASTEL_PURPLE + BOLD + title.toUpperCase() + RESET);
        if (title.equals(CHECKS_SUMMARY)) {
            System.out.printf(headerFormat,
                "Check Name", "PASS", "FAIL", "EXCE", "NAPPL", "CRIT", "HIGH", "MED", "LOW", "INFO");
        }
        System.out.println(PASTEL_PURPLE + "=".repeat(80) + RESET);
    }

    protected void printOverallStatus(List<CheckSummary> summaries) {
        int totalPass  = summaries.stream().mapToInt(CheckSummary::passCount).sum();
        int totalFail  = summaries.stream().mapToInt(CheckSummary::failCount).sum();
        int totalEx    = summaries.stream().mapToInt(CheckSummary::exceptionCount).sum();
        int totalNAppl = summaries.stream().mapToInt(CheckSummary::napplicableCount).sum();
        int total      = totalPass + totalFail + totalEx + totalNAppl;

        int labelWidth = 15;
        int numWidth   = 5;
        int barWidth   = 50;

        int labelField = labelWidth + 2;
        int numField   = numWidth   + 2;
        int barField   = barWidth   + 2;

        String topBorder = SPACE
            + HORIZ_LINE.repeat(labelField) + TOP_CONNECT
            + HORIZ_LINE.repeat(numField)   + TOP_CONNECT
            + HORIZ_LINE.repeat(barField);
        String midBorder = PASTEL_PURPLE    + MID_BEG_CONNECT
            + HORIZ_LINE.repeat(labelField) + CROSS_CONNECT
            + HORIZ_LINE.repeat(numField)   + CROSS_CONNECT
            + HORIZ_LINE.repeat(barField)   + MID_END_CONNECT
            + RESET;
        String botBorder = SPACE 
            + HORIZ_LINE.repeat(labelField) + BOTTOM_CONNECT
            + HORIZ_LINE.repeat(numField)   + BOTTOM_CONNECT
            + HORIZ_LINE.repeat(barField);

        printSectionHeader(FINAL_REPORT);
        System.out.println(PASTEL_PURPLE + topBorder + RESET);

        String rowFmt =
              PASTEL_PURPLE + VERTICAL_LINE + RESET
            + " %-" + labelWidth + "s "
            + PASTEL_PURPLE + VERTICAL_LINE + RESET
            + " %"  + numWidth   + "d "
            + PASTEL_PURPLE + VERTICAL_LINE + RESET
            + " %s "
            + PASTEL_PURPLE + VERTICAL_LINE + RESET
            + "%n";
        
        String blankBar = String.format("%-" + barWidth + "s", "");
        System.out.printf(rowFmt, "Total Checks", total, blankBar);
        System.out.println(midBorder);

        int passBlocks  = Math.min(barWidth, totalPass   * barWidth / Math.max(1, total));
        int failBlocks  = Math.min(barWidth, totalFail   * barWidth / Math.max(1, total));
        int excBlocks   = Math.min(barWidth, totalEx     * barWidth / Math.max(1, total));
        int napplBlocks = Math.min(barWidth, totalNAppl  * barWidth / Math.max(1, total));

        String rawPassBar = BLOCK.repeat(passBlocks);
        String rawFailBar = BLOCK.repeat(failBlocks);
        String rawExcBar  = BLOCK.repeat(excBlocks);
        String rawNAppBar = BLOCK.repeat(napplBlocks);

        String paddedPassBar = String.format("%-" + barWidth + "s", rawPassBar);
        String paddedFailBar = String.format("%-" + barWidth + "s", rawFailBar);
        String paddedExcBar  = String.format("%-" + barWidth + "s", rawExcBar);
        String paddedNAppBar = String.format("%-" + barWidth + "s", rawNAppBar);

        String passBar = PASTEL_GREEN  + paddedPassBar + RESET;
        String failBar = PASTEL_RED    + paddedFailBar + RESET;
        String excBar  = PASTEL_YELLOW + paddedExcBar  + RESET;
        String nAppBar = PASTEL_GRAY   + paddedNAppBar + RESET;

        System.out.printf(rowFmt, "Passed", totalPass, passBar);
        System.out.printf(rowFmt, "Failed", totalFail, failBar);
        System.out.printf(rowFmt, "Exceptions", totalEx, excBar);
        System.out.printf(rowFmt, "Not Applicable", totalNAppl, nAppBar);

        System.out.println(PASTEL_PURPLE + botBorder + RESET);
        printStatisticsBar(totalPass, totalFail, totalEx, total - totalNAppl);
    }

    protected void printRuntime(Duration elapsed) {
        System.out.printf(
            "\n" + PASTEL_BLUE + BOLD + "Runtime: " + RESET + 
            "%02d:%02d.%03d" + PASTEL_BLUE + " (mm:ss.ms)" + RESET + "\n",
            elapsed.toMinutesPart(),
            elapsed.toSecondsPart(),
            elapsed.toMillis() % 1000
        );
    }

    private void printStatisticsBar(int pass, int fail, int exceptions, int total) {
        int width = 60;
        int passWidth = (int) ((double)pass/total * width);
        int failWidth = (int) ((double)fail/total * width);
        int excWidth = width - passWidth - failWidth;
        
        System.out.println("\n" + BOLD + "STATUS DISTRIBUTION" + RESET);
        System.out.println(PASTEL_GREEN + BLOCK.repeat(passWidth) + 
                         PASTEL_RED + BLOCK.repeat(failWidth) +
                         PASTEL_YELLOW + BLOCK.repeat(excWidth) + RESET);
        System.out.printf(
            PASTEL_GREEN + "%.1f%% " + RESET + PASTEL_RED + "%.1f%% " + RESET + 
            PASTEL_YELLOW + "%.1f%%" + RESET + "\n",
            (pass*100.0/total), (fail*100.0/total), (exceptions*100.0/total)
        );
    }
}
