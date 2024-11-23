import { humanizeBaseMetric, humanizeBaseMetricValue } from "./humanizer.ts";
import {
	BaseMetric,
	BaseMetricValue,
	EnvironmentalMetric,
	EnvironmentalMetricValue,
	Metric,
	MetricValue,
	TemporalMetric,
	TemporalMetricValue,
} from "./models.ts";
import {
	calculateBaseScore,
	calculateExploitability,
	calculateImpact,
	calculateIss,
} from "./score-calculator.ts";
import { validate } from "./validator.ts";
import { ValidationResult } from "./validator.ts";

/**
 * Exports utility functions, types, and constants related to CVSS (Common Vulnerability Scoring System).
 * This includes functions for score calculation, validation, and humanization of metric values.
 */
export {
	/**
	 * Function to calculate the base CVSS score based on the CVSS metrics.
	 */
	calculateBaseScore,
	/**
	 * Function to calculate the ISS (Impact Subscore) based on CVSS metrics.
	 */
	calculateIss,
	/**
	 * Function to calculate the impact score of a vulnerability.
	 */
	calculateImpact,
	/**
	 * Function to calculate the exploitability score based on CVSS metrics.
	 */
	calculateExploitability,
	/**
	 * Function to validate the CVSS vector string and metrics.
	 */
	validate,
	/**
	 * Function to humanize the base metric label (e.g., convert it to a user-friendly description).
	 */
	humanizeBaseMetric,
	/**
	 * Function to humanize the value of a base metric (e.g., convert it to a user-friendly description).
	 */
	humanizeBaseMetricValue,
	/**
	 * A type representing a CVSS metric (could be Base, Temporal, or Environmental).
	 */
	Metric,
	/**
	 * A type representing the value of a CVSS metric (could be Base, Temporal, or Environmental).
	 */
	MetricValue,
	/**
	 * A type representing the result of a validation, indicating whether the CVSS string is valid.
	 */
	ValidationResult,
	/**
	 * Enum for base metrics used in CVSS.
	 */
	BaseMetric,
	/**
	 * Enum for temporal metrics used in CVSS.
	 */
	TemporalMetric,
	/**
	 * Enum for environmental metrics used in CVSS.
	 */
	EnvironmentalMetric,
	/**
	 * Type representing possible values for base metrics in CVSS (e.g., "N", "L", "H", etc.).
	 */
	BaseMetricValue,
	/**
	 * Type representing possible values for temporal metrics in CVSS (e.g., "F", "H", "X", etc.).
	 */
	TemporalMetricValue,
	/**
	 * Type representing possible values for environmental metrics in CVSS (e.g., "X", "M", etc.).
	 */
	EnvironmentalMetricValue,
};
