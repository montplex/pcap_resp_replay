package com.montplex.tools;

import java.util.List;

public record TablePrinter(List<String> headers) {

    public void print(List<List<String>> rows) {
        if (headers == null || rows == null) {
            return;
        }

        int columnCount = headers.size();
        int[] columnWidths = new int[columnCount];

        // init column width
        for (int i = 0; i < columnCount; i++) {
            columnWidths[i] = headers.get(i) != null ? headers.get(i).length() : 0;
        }

        // compare column width
        for (List<String> row : rows) {
            for (int j = 0; j < Math.min(row.size(), columnCount); j++) {
                String cell = row.get(j);
                if (cell != null && cell.length() > columnWidths[j]) {
                    columnWidths[j] = cell.length();
                }
            }
        }

        printSeparator(columnWidths);
        printRow(headers, columnWidths);
        printSeparator(columnWidths);

        for (List<String> row : rows) {
            printRow(row, columnWidths);
        }

        printSeparator(columnWidths);
    }

    private void printSeparator(int[] columnWidths) {
        var sb = new StringBuilder();
        sb.append("+");
        for (int width : columnWidths) {
            sb.append("-".repeat(Math.max(0, width + 2)));
            sb.append("+");
        }
        System.out.println(sb);
    }

    private void printRow(List<String> row, int[] columnWidths) {
        var sb = new StringBuilder();
        sb.append("|");
        for (int i = 0; i < columnWidths.length; i++) {
            String cell = (i < row.size() && row.get(i) != null) ? row.get(i) : "";
            sb.append(" ");
            sb.append(cell);
            // 计算填充空格数
            int padding = columnWidths[i] - cell.length();
            sb.append(" ".repeat(Math.max(0, padding)));
            sb.append(" |");
        }
        System.out.println(sb);
    }
}
