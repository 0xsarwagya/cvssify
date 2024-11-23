import { BaseMetric, type Metric, type MetricValue } from "./models.ts";

/**
 * Humanizes the base metric by converting it to a more readable string representation.
 * @param metric - The base metric to be humanized.
 * @returns The humanized string representation of the base metric.
 */
export const humanizeBaseMetric = (metric: Metric): string => {
	switch (metric) {
		case BaseMetric.ATTACK_VECTOR:
			return "Attack Vector";
		case BaseMetric.ATTACK_COMPLEXITY:
			return "Attack Complexity";
		case BaseMetric.PRIVILEGES_REQUIRED:
			return "Privileges Required";
		case BaseMetric.USER_INTERACTION:
			return "User Interaction";
		case BaseMetric.SCOPE:
			return "Scope";
		case BaseMetric.CONFIDENTIALITY:
			return "Confidentiality";
		case BaseMetric.INTEGRITY:
			return "Integrity";
		case BaseMetric.AVAILABILITY:
			return "Availability";
		default:
			return "Unknown";
	}
};

/**
 * Humanizes the base metric value.
 *
 * @param value - The metric value to be humanized.
 * @param metric - The metric type.
 * @returns The humanized string representation of the metric value.
 */
export const humanizeBaseMetricValue = (
	value: MetricValue,
	metric: Metric,
): string => {
	switch (value) {
		case "A":
			return "Adjacent";
		case "C":
			return "Changed";
		case "H":
			return "High";
		case "L":
			return metric === BaseMetric.ATTACK_VECTOR ? "Local" : "Low";
		case "N":
			return metric === BaseMetric.ATTACK_VECTOR ? "Network" : "None";
		case "P":
			return "Physical";
		case "R":
			return "Required";
		case "U":
			return "Unchanged";
		default:
			return "Unknown";
	}
};

/**
 * Stringify a score into a qualitative severity rating string
 */
export const humanizeScore = (score: number): string =>
	score <= 0
		? "None"
		: score <= 3.9
			? "Low"
			: score <= 6.9
				? "Medium"
				: score <= 8.9
					? "High"
					: "Critical";
