package de.tramotech;

import org.apache.commons.cli.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class DuplicateFileFinder {

    public static void main(String[] args) {
        Options options = new Options();

        options.addOption("s", "source", true, "Source directory path (required)");
        options.addOption("t", "target", true, "Target directory path (optional, for comparison)");
        options.addOption("d", "delete-empty", false, "Delete all empty folders in the source directory");
        options.addOption("e", "extensions", true, "Comma-separated list of file extensions to check (e.g., txt,jpg,pdf)");
        options.addOption("h", "help", false, "Show help");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            if (cmd.hasOption("h") || args.length == 0) {
                formatter.printHelp("DuplicateFileFinder", options);
                System.exit(0);
            }

            if (!cmd.hasOption("s")) {
                System.out.println("Source directory is required.");
                formatter.printHelp("DuplicateFileFinder", options);
                System.exit(1);
            }

            Path sourcePath = Paths.get(cmd.getOptionValue("s"));
            if (!Files.isDirectory(sourcePath)) {
                System.out.println("Invalid source directory.");
                System.exit(1);
            }

            Set<String> allowedExtensions = new HashSet<>();
            if (cmd.hasOption("e")) {
                String[] extensions = cmd.getOptionValue("e").split(",");
                for (String ext : extensions) {
                    allowedExtensions.add(ext.trim().toLowerCase());
                }
            }

            if (cmd.hasOption("t")) {
                Path targetPath = Paths.get(cmd.getOptionValue("t"));
                if (!Files.isDirectory(targetPath)) {
                    System.out.println("Invalid target directory.");
                    System.exit(1);
                }
                compareAndDeleteDuplicates(sourcePath, targetPath, allowedExtensions);
            }

            if (cmd.hasOption("d")) {
                deleteEmptyFolders(sourcePath);
            }

            if (!cmd.hasOption("t") && !cmd.hasOption("d")) {
                List<Path> paths = new ArrayList<>();
                paths.add(sourcePath);
                Map<String, List<Path>> duplicates = findDuplicates(paths, allowedExtensions);
                printDuplicates(duplicates);
            }

        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("DuplicateFileFinder", options);
            System.exit(1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Map<String, List<Path>> findDuplicates(List<Path> paths, Set<String> allowedExtensions) throws IOException, NoSuchAlgorithmException {
        Map<String, List<Path>> fileHashes = new HashMap<>();

        for (Path path : paths) {
            Files.walk(path)
                    .filter(Files::isRegularFile)
                    .filter(file -> hasAllowedExtension(file, allowedExtensions))
                    .forEach(file -> {
                        try {
                            String hash = calculateMD5(file);
                            fileHashes.computeIfAbsent(hash, k -> new ArrayList<>()).add(file);
                        } catch (IOException | NoSuchAlgorithmException e) {
                            System.err.println("Failed to process file: " + file);
                        }
                    });
        }

        // Filter out only the entries with more than one file (i.e., duplicates)
        Map<String, List<Path>> duplicates = new HashMap<>();
        for (Map.Entry<String, List<Path>> entry : fileHashes.entrySet()) {
            if (entry.getValue().size() > 1) {
                duplicates.put(entry.getKey(), entry.getValue());
            }
        }

        return duplicates;
    }

    private static boolean hasAllowedExtension(Path file, Set<String> allowedExtensions) {
        if (allowedExtensions.isEmpty()) {
            return true; // No extensions specified, include all files
        }
        String fileName = file.getFileName().toString().toLowerCase();
        return allowedExtensions.stream().anyMatch(fileName::endsWith);
    }

    private static void compareAndDeleteDuplicates(Path sourcePath, Path targetPath, Set<String> allowedExtensions) throws IOException, NoSuchAlgorithmException {
        Map<String, Path> targetHashes = new HashMap<>();

        Files.walk(targetPath)
                .filter(Files::isRegularFile)
                .filter(file -> hasAllowedExtension(file, allowedExtensions))
                .forEach(file -> {
                    try {
                        String hash = calculateMD5(file);
                        targetHashes.put(hash, file);
                    } catch (IOException | NoSuchAlgorithmException e) {
                        System.err.println("Failed to process file in target path: " + file);
                    }
                });

        Files.walk(sourcePath)
                .filter(Files::isRegularFile)
                .filter(file -> hasAllowedExtension(file, allowedExtensions))
                .forEach(file -> {
                    try {
                        String hash = calculateMD5(file);
                        if (targetHashes.containsKey(hash)) {
                            System.out.println("Duplicate found and deleting file: " + file);
                            Files.delete(file);
                        }
                    } catch (IOException | NoSuchAlgorithmException e) {
                        System.err.println("Failed to process file in source path: " + file);
                    }
                });
    }

    private static void deleteEmptyFolders(Path directory) throws IOException {
        Files.walk(directory)
                .sorted((a, b) -> b.getNameCount() - a.getNameCount())
                .filter(Files::isDirectory)
                .forEach(dir -> {
                    try {
                        if (isDirectoryEmpty(dir)) {
                            Files.delete(dir);
                            System.out.println("Deleted empty directory: " + dir);
                        }
                    } catch (IOException e) {
                        System.err.println("Failed to delete directory: " + dir);
                    }
                });
    }

    private static boolean isDirectoryEmpty(Path dir) throws IOException {
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(dir)) {
            for (Path entry : dirStream) {
                String fileName = entry.getFileName().toString();
                if (!fileName.equals(".DS_Store")) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String calculateMD5(Path file) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (FileInputStream fis = new FileInputStream(file.toFile())) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                md.update(buffer, 0, bytesRead);
            }
        }

        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void printDuplicates(Map<String, List<Path>> duplicates) {
        if (duplicates.isEmpty()) {
            System.out.println("No duplicate files found.");
        } else {
            System.out.println("Duplicate files found:");
            duplicates.forEach((hash, files) -> {
                System.out.println("MD5: " + hash);
                files.forEach(file -> System.out.println(" - " + file));
            });
        }
    }
}

