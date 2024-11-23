/**
 * Enum representing the base metrics used in CVSS (Common Vulnerability Scoring System).
 */
export enum BaseMetric {
	ATTACK_VECTOR = "AV",
	ATTACK_COMPLEXITY = "AC",
	PRIVILEGES_REQUIRED = "PR",
	USER_INTERACTION = "UI",
	SCOPE = "S",
	CONFIDENTIALITY = "C",
	INTEGRITY = "I",
	AVAILABILITY = "A",
}

/**
 * Enum representing the temporal metrics used in CVSS.
 */
export enum TemporalMetric {
	EXPLOIT_CODE_MATURITY = "E",
	REMEDIATION_LEVEL = "RL",
	REPORT_CONFIDENCE = "RC",
}

/**
 * Enum representing the environmental metrics used in CVSS.
 */
export enum EnvironmentalMetric {
	CONFIDENTIALITY_REQUIREMENT = "CR",
	INTEGRITY_REQUIREMENT = "IR",
	AVAILABILITY_REQUIREMENT = "AR",
	MODIFIED_ATTACK_VECTOR = "MAV",
	MODIFIED_ATTACK_COMPLEXITY = "MAC",
	MODIFIED_PRIVILEGES_REQUIRED = "MPR",
	MODIFIED_USER_INTERACTION = "MUI",
	MODIFIED_SCOPE = "MS",
	MODIFIED_CONFIDENTIALITY = "MC",
	MODIFIED_INTEGRITY = "MI",
	MODIFIED_AVAILABILITY = "MA",
}

/**
 * Type representing any CVSS metric (Base, Temporal, or Environmental).
 */
export type Metric = BaseMetric | TemporalMetric | EnvironmentalMetric;

/**
 * Type representing an array of metrics.
 */
export type Metrics = readonly Metric[];

/**
 * Type representing possible values for base metrics (e.g., Confidentiality, Integrity, etc.).
 */
export type BaseMetricValue = "A" | "C" | "H" | "L" | "N" | "P" | "R" | "U";

/**
 * Type representing possible values for temporal metrics (e.g., Exploit Code Maturity, Remediation Level, etc.).
 */
export type TemporalMetricValue =
	| "X"
	| "F"
	| "H"
	| "O"
	| "T"
	| "W"
	| "U"
	| "P"
	| "C"
	| "R";

/**
 * Type representing possible values for environmental metrics (e.g., Modified Attack Vector, Confidentiality Requirement, etc.).
 */
export type EnvironmentalMetricValue = BaseMetricValue | "M" | "X";

/**
 * Type representing any value of a CVSS metric (Base, Temporal, or Environmental).
 */
export type MetricValue =
	| BaseMetricValue
	| TemporalMetricValue
	| EnvironmentalMetricValue;

/**
 * Type representing a mapping of metrics to their corresponding values.
 * This maps each metric to an array of possible values.
 */
export type MetricValues<
	M extends Metric = Metric,
	V extends MetricValue = MetricValue,
> = Record<M, V[]>;

/**
 * Array of base metrics used in CVSS.
 */
export const baseMetrics: readonly BaseMetric[] = [
	BaseMetric.ATTACK_VECTOR,
	BaseMetric.ATTACK_COMPLEXITY,
	BaseMetric.PRIVILEGES_REQUIRED,
	BaseMetric.USER_INTERACTION,
	BaseMetric.SCOPE,
	BaseMetric.CONFIDENTIALITY,
	BaseMetric.INTEGRITY,
	BaseMetric.AVAILABILITY,
];

/**
 * Array of temporal metrics used in CVSS.
 */
export const temporalMetrics: readonly TemporalMetric[] = [
	TemporalMetric.EXPLOIT_CODE_MATURITY,
	TemporalMetric.REMEDIATION_LEVEL,
	TemporalMetric.REPORT_CONFIDENCE,
];

/**
 * Array of environmental metrics used in CVSS.
 */
export const environmentalMetrics: readonly EnvironmentalMetric[] = [
	EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
	EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
	EnvironmentalMetric.INTEGRITY_REQUIREMENT,
	EnvironmentalMetric.MODIFIED_ATTACK_VECTOR,
	EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY,
	EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED,
	EnvironmentalMetric.MODIFIED_USER_INTERACTION,
	EnvironmentalMetric.MODIFIED_SCOPE,
	EnvironmentalMetric.MODIFIED_CONFIDENTIALITY,
	EnvironmentalMetric.MODIFIED_INTEGRITY,
	EnvironmentalMetric.MODIFIED_AVAILABILITY,
];

/**
 * A mapping of base metrics to their possible values.
 */
export const baseMetricValues: MetricValues<BaseMetric, BaseMetricValue> = {
	[BaseMetric.ATTACK_VECTOR]: ["N", "A", "L", "P"],
	[BaseMetric.ATTACK_COMPLEXITY]: ["L", "H"],
	[BaseMetric.PRIVILEGES_REQUIRED]: ["N", "L", "H"],
	[BaseMetric.USER_INTERACTION]: ["N", "R"],
	[BaseMetric.SCOPE]: ["U", "C"],
	[BaseMetric.CONFIDENTIALITY]: ["N", "L", "H"],
	[BaseMetric.INTEGRITY]: ["N", "L", "H"],
	[BaseMetric.AVAILABILITY]: ["N", "L", "H"],
};

/**
 * A mapping of temporal metrics to their possible values.
 */
export const temporalMetricValues: MetricValues<
	TemporalMetric,
	TemporalMetricValue
> = {
	[TemporalMetric.EXPLOIT_CODE_MATURITY]: ["X", "H", "F", "P", "U"],
	[TemporalMetric.REMEDIATION_LEVEL]: ["X", "U", "W", "T", "O"],
	[TemporalMetric.REPORT_CONFIDENCE]: ["X", "C", "R", "U"],
};

/**
 * A mapping of environmental metrics to their possible values.
 */
export const environmentalMetricValues: MetricValues<
	EnvironmentalMetric,
	EnvironmentalMetricValue
> = {
	[EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: ["X", "H", "M", "L"],
	[EnvironmentalMetric.INTEGRITY_REQUIREMENT]: ["X", "H", "M", "L"],
	[EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: ["X", "H", "M", "L"],
	[EnvironmentalMetric.MODIFIED_ATTACK_VECTOR]: ["X", "N", "A", "L", "P"],
	[EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY]: ["X", "L", "H"],
	[EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED]: ["X", "N", "L", "H"],
	[EnvironmentalMetric.MODIFIED_USER_INTERACTION]: ["X", "N", "R"],
	[EnvironmentalMetric.MODIFIED_SCOPE]: ["X", "U", "C"],
	[EnvironmentalMetric.MODIFIED_CONFIDENTIALITY]: ["X", "N", "L", "H"],
	[EnvironmentalMetric.MODIFIED_INTEGRITY]: ["X", "N", "L", "H"],
	[EnvironmentalMetric.MODIFIED_AVAILABILITY]: ["X", "N", "L", "H"],
};
