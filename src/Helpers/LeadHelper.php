<?php

namespace InsuranceCore\Helpers\Helpers;

if (!function_exists('generateLeadID')) {
    /**
     * Generate a unique lead ID in the format ASK/YYYY/MM/RANDOM
     * 
     * @return string
     */
    function generateLeadID()
    {
        // Get the current year and month
        $year = date("Y"); // e.g., 2024
        $month = date("m"); // e.g., 12

        // Generate an array of digits 0-9 and shuffle to ensure randomness
        $numbers = range(0, 9);
        shuffle($numbers);

        // Pick the first 6 unique digits
        $randomNumbers = array_slice($numbers, 0, 6);

        // Combine "ASK", year, month, and random numbers with slashes
        return "ASK/" .
            $year .
            "/" .
            $month .
            "/" .
            implode("", $randomNumbers);
    }
} 