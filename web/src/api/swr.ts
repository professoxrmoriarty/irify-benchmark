import useSWR, { type SWRConfiguration } from 'swr'
import {
  getProject,
  getProjectCases,
  getProjectDiagnosis,
  getProjectFiles,
  getFileContent,
  listProjects,
} from './client'
import type { Annotation, DiagnosisReport, FileEntry, Project } from '../types'

export type ProjectDiagnosisMap = Record<string, DiagnosisReport | null>

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: true,
  revalidateIfStale: true,
  dedupingInterval: 2000,
  keepPreviousData: true,
}

// Project list
export function useProjects(config?: SWRConfiguration) {
  return useSWR<Project[]>('/api/projects', listProjects, { ...defaultConfig, ...config })
}

// Single project metadata
export function useProject(projectId: string | undefined, config?: SWRConfiguration) {
  return useSWR<Project>(
    projectId ? [`/api/projects`, projectId] : null,
    () => getProject(projectId!),
    { ...defaultConfig, ...config }
  )
}

// Source file tree
export function useProjectFiles(projectId: string | undefined, config?: SWRConfiguration) {
  return useSWR<FileEntry>(
    projectId ? [`/api/projects/files`, projectId] : null,
    () => getProjectFiles(projectId!),
    { ...defaultConfig, ...config }
  )
}

// Ground-truth cases
export function useProjectCases(projectId: string | undefined, config?: SWRConfiguration) {
  return useSWR<Annotation>(
    projectId ? [`/api/projects/cases`, projectId] : null,
    () => getProjectCases(projectId!) as Promise<Annotation>,
    { ...defaultConfig, ...config }
  )
}

// File content (code preview)
export function useFileContent(
  projectId: string | undefined,
  path: string | undefined,
  config?: SWRConfiguration
) {
  return useSWR<string>(
    projectId && path ? [`/api/projects/file-content`, projectId, path] : null,
    () => getFileContent(projectId!, path!),
    { ...defaultConfig, ...config }
  )
}

// Diagnosis report
export function useProjectDiagnosis(
  projectId: string | undefined,
  engine?: string,
  version?: string,
  config?: SWRConfiguration
) {
  return useSWR<DiagnosisReport>(
    projectId ? ['/api/projects/diagnosis', projectId, engine, version] : null,
    () => getProjectDiagnosis(projectId!, engine, version),
    { ...defaultConfig, ...config }
  )
}

// Batch diagnosis for a list of projects (used by Dashboard).
export function useProjectDiagnoses(
  projectIds: string[],
  engine?: string,
  config?: SWRConfiguration
) {
  return useSWR<ProjectDiagnosisMap>(
    projectIds.length ? ['/api/projects/diagnoses', ...projectIds.sort(), engine] : null,
    async () => {
      const result: ProjectDiagnosisMap = {}
      await Promise.all(
        projectIds.map(async (pid) => {
          try {
            result[pid] = await getProjectDiagnosis(pid, engine)
          } catch {
            result[pid] = null
          }
        })
      )
      return result
    },
    { ...defaultConfig, ...config }
  )
}
